package organisations

import (
	"crypto/ecdsa"
	"database/sql"

	"github.com/golang/protobuf/proto"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/protocol/protobuf"
)

type Persistence struct {
	db *sql.DB
}

func (p *Persistence) SaveOrganisation(organisation *Organisation) error {
	id := organisation.ID()
	privateKey := organisation.PrivateKey()
	description, err := organisation.DescriptionBytes()
	if err != nil {
		return err
	}

	_, err = p.db.Exec(`INSERT INTO organisations_organisations (id, private_key, description) VALUES (?, ?, ?)`, id, crypto.FromECDSA(privateKey), description)
	return err
}

func (p *Persistence) AllOrganisations() ([]*Organisation, error) {
	var response []*Organisation

	rows, err := p.db.Query(`SELECT id, private_key, description FROM organisations_organisations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var publicKeyBytes, privateKeyBytes, descriptionBytes []byte
		err := rows.Scan(&publicKeyBytes, &privateKeyBytes, &descriptionBytes)

		if err != nil {
			return nil, err
		}
		var privateKey *ecdsa.PrivateKey

		if privateKeyBytes != nil {
			privateKey, err = crypto.ToECDSA(privateKeyBytes)
			if err != nil {
				return nil, err
			}
		}
		description := &protobuf.OrganisationDescription{}

		err = proto.Unmarshal(descriptionBytes, description)
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
			ID:                               id,
		}

		response = append(response, New(config))
	}

	return response, nil
}
