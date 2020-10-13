package organisations

import (
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
	persistence *Persistence
	logger      *zap.Logger
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

func (m *Manager) All() ([]*Organisation, error) {
	return m.persistence.AllOrganisations()
}

// CreateOrganisation takes a description, generates an ID for it, saves it and return it
func (m *Manager) CreateOrganisation(description *protobuf.OrganisationDescription) (*Organisation, error) {
	err := ValidateOrganisationDescription(description)
	if err != nil {
		return nil, err
	}

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
	err = m.persistence.SaveOrganisation(org)
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

	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, nil, err
	}

	// Advertise changes

	return org, changes, nil
}

func (m *Manager) HandleWrappedOrganisationDescriptionMessage(payload []byte) (*Organisation, error) {
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

	id := crypto.CompressPubkey(signer)
	org, err := m.persistence.GetByID(id)
	if err != nil {
		return nil, err
	}

	if org == nil {
		config := Config{
			OrganisationDescription:          description,
			MarshaledOrganisationDescription: payload,
			ID:                               signer,
		}

		org = New(config)
	}

	m.logger.Debug("Handling wrapped organisation description message", zap.Any("DESC", description))
	_, err = org.HandleOrganisationDescription(signer, description)
	if err != nil {
		return nil, err
	}

	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, err
	}

	return org, nil
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
