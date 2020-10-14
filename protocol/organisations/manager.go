package organisations

import (
	"crypto/ecdsa"
	"database/sql"

	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/protobuf"
)

type Manager struct {
	persistence   *Persistence
	subscriptions []chan []*Organisation
	logger        *zap.Logger
}

func NewManager(db *sql.DB, logger *zap.Logger) (*Manager, error) {
	var err error
	if logger, err = zap.NewDevelopment(); err != nil {
		return nil, errors.Wrap(err, "failed to create a logger")
	}

	return &Manager{
		logger: logger,
		persistence: &Persistence{
			db: db,
		},
	}, nil
}

func (m *Manager) Subscribe() chan []*Organisation {
	subscription := make(chan []*Organisation, 100)
	m.subscriptions = append(m.subscriptions, subscription)
	return subscription
}

func (m *Manager) Stop() error {
	for _, c := range m.subscriptions {
		close(c)
	}
	return nil
}

func (m *Manager) publish() error {
	organisations, err := m.persistence.CreatedOrganisations()
	if err != nil {
		return err
	}
	for _, s := range m.subscriptions {
		select {
		case s <- organisations:
		default:
			m.logger.Warn("subscription channel full, dropping message")
		}
	}
	return nil
}

func (m *Manager) All() ([]*Organisation, error) {
	return m.persistence.AllOrganisations()
}

func (m *Manager) Joined() ([]*Organisation, error) {
	return m.persistence.JoinedOrganisations()
}

func (m *Manager) Created() ([]*Organisation, error) {
	return m.persistence.CreatedOrganisations()
}

// CreateOrganisation takes a description, generates an ID for it, saves it and return it
func (m *Manager) CreateOrganisation(description *protobuf.OrganisationDescription) (*Organisation, error) {
	err := ValidateOrganisationDescription(description)
	if err != nil {
		return nil, err
	}

	description.Clock = 1

	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	config := Config{
		ID:                      &key.PublicKey,
		PrivateKey:              key,
		Joined:                  true,
		OrganisationDescription: description,
	}
	org := New(config)
	m.logger.Debug("SAVING", zap.Any("ORG", org))
	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, err
	}

	err = m.publish()
	if err != nil {
		return nil, err
	}

	return org, nil
}

func (m *Manager) CreateChat(idString string, chat *protobuf.OrganisationChat) (*Organisation, *OrganisationChanges, error) {
	org, err := m.GetByIDString(idString)
	if err != nil {
		return nil, nil, err
	}
	if org == nil {
		return nil, nil, ErrOrgNotFound
	}
	chatID := uuid.New().String()
	changes, err := org.CreateChat(chatID, chat)
	if err != nil {
		return nil, nil, err
	}

	m.logger.Debug("SAVING", zap.Any("ORG", org))
	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, nil, err
	}

	// Advertise changes
	err = m.publish()
	if err != nil {
		return nil, nil, err
	}

	return org, changes, nil
}

func (m *Manager) HandleOrganisationDescriptionMessage(signer *ecdsa.PublicKey, description *protobuf.OrganisationDescription, payload []byte) (*Organisation, error) {
	id := crypto.CompressPubkey(signer)
	org, err := m.persistence.GetByID(id)
	if err != nil {
		return nil, err
	}

	if org == nil {
		m.logger.Debug("initializing new organisation")
		config := Config{
			OrganisationDescription:          description,
			MarshaledOrganisationDescription: payload,
			ID:                               signer,
		}

		org = New(config)
	}

	m.logger.Debug("Handling organisation description message", zap.Any("DESC", description))
	m.logger.Debug("Handling organisation description message", zap.Any("DESC2", description.Clock))
	_, err = org.HandleOrganisationDescription(signer, description, payload)
	if err != nil {
		return nil, err
	}

	m.logger.Debug("Handled organisation description message", zap.Any("DESC", org))
	m.logger.Debug("SAVING", zap.Any("ORG", org))
	m.logger.Debug("PAYLOAD", zap.Any("payload", payload))
	m.logger.Debug("SAVING2", zap.Any("CONFIG", org.config))

	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, err
	}

	return org, nil
}

func (m *Manager) HandleWrappedOrganisationDescriptionMessage(payload []byte) (*Organisation, error) {
	m.logger.Debug("Handling wrapped organisation description message")

	applicationMetadataMessage := &protobuf.ApplicationMetadataMessage{}
	err := proto.Unmarshal(payload, applicationMetadataMessage)
	if err != nil {
		return nil, err
	}
	if applicationMetadataMessage.Type != protobuf.ApplicationMetadataMessage_ORGANISATION_DESCRIPTION {
		return nil, ErrInvalidMessage
	}
	signer, err := applicationMetadataMessage.RecoverKey()
	if err != nil {
		return nil, err
	}

	description := &protobuf.OrganisationDescription{}

	err = proto.Unmarshal(applicationMetadataMessage.Payload, description)
	if err != nil {
		return nil, err
	}

	return m.HandleOrganisationDescriptionMessage(signer, description, payload)
}

func (m *Manager) JoinOrganisation(idString string) (*Organisation, error) {
	org, err := m.GetByIDString(idString)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, ErrOrgNotFound
	}
	org.Join()
	m.logger.Debug("SAVING", zap.Any("ORG", org))
	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, err
	}
	return org, nil
}

func (m *Manager) LeaveOrganisation(idString string) (*Organisation, error) {
	org, err := m.GetByIDString(idString)
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, ErrOrgNotFound
	}
	org.Leave()
	m.logger.Debug("SAVING", zap.Any("ORG", org))
	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, err
	}
	return org, nil
}

func (m *Manager) GetByIDString(idString string) (*Organisation, error) {
	id, err := types.DecodeHex(idString)
	if err != nil {
		return nil, err
	}
	return m.persistence.GetByID(id)
}
