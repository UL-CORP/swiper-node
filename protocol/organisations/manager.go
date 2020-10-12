package organisations

import (
	"database/sql"

	"github.com/status-im/status-go/eth-node/crypto"
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
