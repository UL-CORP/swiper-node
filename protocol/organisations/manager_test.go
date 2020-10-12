package organisations

import (
	"testing"

	"github.com/golang/protobuf/proto"
	_ "github.com/mutecomm/go-sqlcipher" // require go-sqlcipher that overrides default implementation

	"github.com/status-im/status-go/protocol/protobuf"
	"github.com/status-im/status-go/protocol/sqlite"
	"github.com/stretchr/testify/suite"
)

func TestManagerSuite(t *testing.T) {
	suite.Run(t, new(ManagerSuite))
}

type ManagerSuite struct {
	suite.Suite
	manager *Manager
}

func (s *ManagerSuite) SetupTest() {
	db, err := sqlite.OpenInMemory()
	s.Require().NoError(err)
	s.manager = NewManager(db)
}

func (s *ManagerSuite) TestCreateOrganisation() {
	description := &protobuf.OrganisationDescription{
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status",
			Description: "status organisation description",
		},
	}

	organisation, err := s.manager.CreateOrganisation(description)
	s.Require().NoError(err)
	s.Require().NotNil(organisation)

	organisations, err := s.manager.All()
	s.Require().NoError(err)
	s.Require().Len(organisations, 1)
	s.Require().Equal(organisation.ID(), organisations[0].ID())
	s.Require().Equal(organisation.PrivateKey(), organisations[0].PrivateKey())
	s.Require().True(proto.Equal(organisation.config.OrganisationDescription, organisations[0].config.OrganisationDescription))
}
