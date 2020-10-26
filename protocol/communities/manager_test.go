package communities

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
	m, err := NewManager(db, nil)
	s.Require().NoError(err)
	s.manager = m
}

func (s *ManagerSuite) TestCreateCommunity() {
	description := &protobuf.CommunityDescription{
		Permissions: &protobuf.CommunityPermissions{
			Access: protobuf.CommunityPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status",
			Description: "status community description",
		},
	}

	community, err := s.manager.CreateCommunity(description)
	s.Require().NoError(err)
	s.Require().NotNil(community)

	communities, err := s.manager.All()
	s.Require().NoError(err)
	s.Require().Len(communities, 1)
	s.Require().Equal(community.ID(), communities[0].ID())
	s.Require().Equal(community.PrivateKey(), communities[0].PrivateKey())
	s.Require().True(proto.Equal(community.config.CommunityDescription, communities[0].config.CommunityDescription))
}
