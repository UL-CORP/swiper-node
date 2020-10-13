package organisations

import (
	"database/sql"

	"github.com/golang/protobuf/proto"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/protobuf"
)

type Manager struct {
	persistence *Persistence
}

func NewManager(db *sql.DB) *Manager {

	return &Manager{
		persistence: &Persistence{
			db: db,
		},
	}
}

func (m *Manager) All() ([]*Organisation, error) {
	return m.persistence.AllOrganisations()
}

// TODO: validate
// CreateOrganisation takes a description, generates an ID for it, saves it and return it
func (m *Manager) CreateOrganisation(description *protobuf.OrganisationDescription) (*Organisation, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	config := Config{
		ID:                      &key.PublicKey,
		PrivateKey:              key,
		OrganisationDescription: description,
	}
	org := New(config)
	err = m.persistence.SaveOrganisation(org)
	if err != nil {
		return nil, err
	}

	return org, nil
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

func (m *Manager) GetByIDString(idString string) (*Organisation, error) {
	id, err := types.DecodeHex(idString)
	if err != nil {
		return nil, err
	}
	return m.persistence.GetByID(id)
}
