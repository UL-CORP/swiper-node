package organisations

import (
	"crypto/ecdsa"
	"database/sql"

	"github.com/golang/protobuf/proto"
	"go.uber.org/zap"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/protocol/protobuf"
)

type Persistence struct {
	db     *sql.DB
	logger *zap.Logger
}

func (p *Persistence) SaveOrganisation(organisation *Organisation) error {
	id := organisation.ID()
	privateKey := organisation.PrivateKey()
	description, err := organisation.ToBytes()
	if err != nil {
		return err
	}

	_, err = p.db.Exec(`INSERT INTO organisations_organisations (id, private_key, description, joined) VALUES (?, ?, ?,?)`, id, crypto.FromECDSA(privateKey), description, organisation.config.Joined)
	return err
}

func (p *Persistence) queryOrganisations(query string) ([]*Organisation, error) {
	var response []*Organisation

	rows, err := p.db.Query(`SELECT id, private_key, description,joined FROM organisations_organisations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var publicKeyBytes, privateKeyBytes, descriptionBytes []byte
		var joined bool
		err := rows.Scan(&publicKeyBytes, &privateKeyBytes, &descriptionBytes, &joined)
		if err != nil {
			return nil, err
		}

		org, err := unmarshalOrganisationFromDB(publicKeyBytes, privateKeyBytes, descriptionBytes, joined, p.logger)
		if err != nil {
			return nil, err
		}
		response = append(response, org)
	}

	return response, nil

}

func (p *Persistence) AllOrganisations() ([]*Organisation, error) {
	query := `SELECT id, private_key, description,joined FROM organisations_organisations`
	return p.queryOrganisations(query)
}

func (p *Persistence) JoinedOrganisations() ([]*Organisation, error) {
	query := `SELECT id, private_key, description,joined FROM organisations_organisations WHERE joined`
	return p.queryOrganisations(query)
}

func (p *Persistence) CreatedOrganisations() ([]*Organisation, error) {
	query := `SELECT id, private_key, description,joined FROM organisations_organisations WHERE private_key IS NOT NULL`
	return p.queryOrganisations(query)
}

func (p *Persistence) GetByID(id []byte) (*Organisation, error) {
	var publicKeyBytes, privateKeyBytes, descriptionBytes []byte
	var joined bool

	err := p.db.QueryRow(`SELECT id, private_key, description, joined FROM organisations_organisations WHERE id = ?`, id).Scan(&publicKeyBytes, &privateKeyBytes, &descriptionBytes, &joined)

	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return unmarshalOrganisationFromDB(publicKeyBytes, privateKeyBytes, descriptionBytes, joined, p.logger)
}

func unmarshalOrganisationFromDB(publicKeyBytes, privateKeyBytes, descriptionBytes []byte, joined bool, logger *zap.Logger) (*Organisation, error) {

	var privateKey *ecdsa.PrivateKey
	var err error

	if privateKeyBytes != nil {
		privateKey, err = crypto.ToECDSA(privateKeyBytes)
		if err != nil {
			return nil, err
		}
	}
	metadata := &protobuf.ApplicationMetadataMessage{}

	err = proto.Unmarshal(descriptionBytes, metadata)
	if err != nil {
		return nil, err
	}

	description := &protobuf.OrganisationDescription{}

	err = proto.Unmarshal(metadata.Payload, description)
	if err != nil {
		return nil, err
	}

	id, err := crypto.DecompressPubkey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	config := Config{
		PrivateKey:                       privateKey,
		OrganisationDescription:          description,
		MarshaledOrganisationDescription: descriptionBytes,
		Logger:                           logger,
		ID:                               id,
		Joined:                           joined,
	}
	return New(config)
}
