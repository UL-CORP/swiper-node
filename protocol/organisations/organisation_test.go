package organisations

import (
	"crypto/ecdsa"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/suite"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/protobuf"
)

func TestOrganisationSuite(t *testing.T) {
	suite.Run(t, new(OrganisationSuite))
}

const testChatID1 = "chat-id-1"
const testChatID2 = "chat-id-2"

type OrganisationSuite struct {
	suite.Suite

	identity       *ecdsa.PrivateKey
	organisationID []byte

	member1 *ecdsa.PrivateKey
	member2 *ecdsa.PrivateKey
	member3 *ecdsa.PrivateKey

	member1Key string
	member2Key string
	member3Key string
}

func (s *OrganisationSuite) SetupTest() {
	identity, err := crypto.GenerateKey()
	s.Require().NoError(err)
	s.identity = identity
	s.organisationID = crypto.CompressPubkey(&identity.PublicKey)

	member1, err := crypto.GenerateKey()
	s.Require().NoError(err)
	s.member1 = member1

	member2, err := crypto.GenerateKey()
	s.Require().NoError(err)
	s.member2 = member2

	member3, err := crypto.GenerateKey()
	s.Require().NoError(err)
	s.member3 = member3

	s.member1Key = common.PubkeyToHex(&s.member1.PublicKey)
	s.member2Key = common.PubkeyToHex(&s.member2.PublicKey)
	s.member3Key = common.PubkeyToHex(&s.member3.PublicKey)

}

func (s *OrganisationSuite) TestHandleRequestJoin() {
	description := &protobuf.OrganisationDescription{}

	key, err := crypto.GenerateKey()
	s.Require().NoError(err)

	signer := &key.PublicKey

	request := &protobuf.OrganisationRequestJoin{
		EnsName:        "donvanvliet.stateofus.eth",
		OrganisationId: s.organisationID,
	}

	requestWithChatID := &protobuf.OrganisationRequestJoin{
		EnsName:        "donvanvliet.stateofus.eth",
		OrganisationId: s.organisationID,
		ChatId:         testChatID1,
	}

	requestWithoutENS := &protobuf.OrganisationRequestJoin{
		OrganisationId: s.organisationID,
	}

	requestWithChatWithoutENS := &protobuf.OrganisationRequestJoin{
		OrganisationId: s.organisationID,
		ChatId:         testChatID1,
	}

	// MATRIX
	// NO_MEMBERHSIP - NO_MEMBERSHIP -> Error
	// NO_MEMBRISHIP - INVITATION_ONLY -> Error
	// NO_MEMBERSHIP - ON_REQUEST -> Success
	// INVITATION_ONLY - NO_MEMBERSHIP -> Invalid
	// INVITATION_ONLY - INVITATION_ONLY -> Error
	// INVITATION_ONLY - ON_REQUEST -> Invalid
	// ON_REQUEST - NO_MEMBRERSHIP -> Invalid
	// ON_REQUEST - INVITATION_ONLY -> Error
	// ON_REQUEST - ON_REQUEST -> Fine

	testCases := []struct {
		name    string
		config  Config
		request *protobuf.OrganisationRequestJoin
		signer  *ecdsa.PublicKey
		err     error
	}{
		{
			name:    "on-request access to organisation",
			config:  s.configOnRequest(),
			signer:  signer,
			request: request,
			err:     nil,
		},
		{
			name:    "not admin",
			config:  Config{OrganisationDescription: description},
			signer:  signer,
			request: request,
			err:     ErrNotAdmin,
		},
		{
			name:    "invitation-only",
			config:  s.configInvitationOnly(),
			signer:  signer,
			request: request,
			err:     ErrCantRequestAccess,
		},
		{
			name:    "ens-only org and missing ens",
			config:  s.configENSOnly(),
			signer:  signer,
			request: requestWithoutENS,
			err:     ErrCantRequestAccess,
		},
		{
			name:    "ens-only chat and missing ens",
			config:  s.configChatENSOnly(),
			signer:  signer,
			request: requestWithChatWithoutENS,
			err:     ErrCantRequestAccess,
		},
		{
			name:    "missing chat",
			config:  s.configOnRequest(),
			signer:  signer,
			request: requestWithChatID,
			err:     ErrChatNotFound,
		},
		// Org-Chat combinations
		// NO_MEMBERSHIP-NO_MEMBERSHIP = error as you should not be
		// requesting access
		{
			name:    "no-membership org with no-membeship chat",
			config:  s.configNoMembershipOrgNoMembershipChat(),
			signer:  signer,
			request: requestWithChatID,
			err:     ErrCantRequestAccess,
		},
		// NO_MEMBERSHIP-INVITATION_ONLY = error as it's invitation only
		{
			name:    "no-membership org with no-membeship chat",
			config:  s.configNoMembershipOrgInvitationOnlyChat(),
			signer:  signer,
			request: requestWithChatID,
			err:     ErrCantRequestAccess,
		},
		// NO_MEMBERSHIP-ON_REQUEST = this is a valid case
		{
			name:    "no-membership org with on-request chat",
			config:  s.configNoMembershipOrgOnRequestChat(),
			signer:  signer,
			request: requestWithChatID,
		},
		// INVITATION_ONLY-INVITATION_ONLY error as it's invitation only
		{
			name:    "invitation-only org with invitation-only chat",
			config:  s.configInvitationOnlyOrgInvitationOnlyChat(),
			signer:  signer,
			request: requestWithChatID,
			err:     ErrCantRequestAccess,
		},
		// ON_REQUEST-INVITATION_ONLY error as it's invitation only
		{
			name:    "on-request org with invitation-only chat",
			config:  s.configOnRequestOrgInvitationOnlyChat(),
			signer:  signer,
			request: requestWithChatID,
			err:     ErrCantRequestAccess,
		},
		// ON_REQUEST-INVITATION_ONLY error as it's invitation only
		{
			name:    "on-request org with invitation-only chat",
			config:  s.configOnRequestOrgInvitationOnlyChat(),
			signer:  signer,
			request: requestWithChatID,
			err:     ErrCantRequestAccess,
		},
		// ON_REQUEST-ON_REQUEST success
		{
			name:    "on-request org with on-request chat",
			config:  s.configOnRequestOrgOnRequestChat(),
			signer:  signer,
			request: requestWithChatID,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			org := New(tc.config)
			err := org.HandleRequestJoin(tc.signer, tc.request)
			s.Require().Equal(tc.err, err)
		})
	}
}

// Test New to make sure it validates the description

func (s *OrganisationSuite) TestHandleOrganisationDescription() {
	key, err := crypto.GenerateKey()
	s.Require().NoError(err)

	signer := &key.PublicKey

	// Test Cases
	// 0) Wrong signer
	// 1) Identical +
	// 2) Outdated +
	// 3) Invalid
	// 4) Member Added +
	// 5) Member removed +
	// 6) Chat added
	// 7) Chat removed
	// 8) Member added in chat +
	// 9) Member removed in chat +
	// 10) Permission changes in org/chat
	testCases := []struct {
		name        string
		description func(*Organisation) *protobuf.OrganisationDescription
		changes     func(*Organisation) *OrganisationChanges
		signer      *ecdsa.PublicKey
		err         error
	}{
		{
			name:        "updated version but no changes",
			description: s.identicalOrganisationDescription,
			signer:      signer,
			changes:     func(_ *Organisation) *OrganisationChanges { return emptyOrganisationChanges() },
			err:         nil,
		},
		{
			name:        "updated version but lower clock",
			description: s.oldOrganisationDescription,
			signer:      signer,
			changes:     func(_ *Organisation) *OrganisationChanges { return emptyOrganisationChanges() },
			err:         nil,
		},
		{
			name:        "removed member from org",
			description: s.removedMemberOrganisationDescription,
			signer:      signer,
			changes: func(org *Organisation) *OrganisationChanges {
				changes := emptyOrganisationChanges()
				changes.MembersRemoved[s.member1Key] = &protobuf.OrganisationMember{}
				changes.ChatsModified[testChatID1] = &OrganisationChatChanges{
					MembersAdded:   make(map[string]*protobuf.OrganisationMember),
					MembersRemoved: make(map[string]*protobuf.OrganisationMember),
				}
				changes.ChatsModified[testChatID1].MembersRemoved[s.member1Key] = &protobuf.OrganisationMember{}

				return changes
			},
			err: nil,
		},
		{
			name:        "added member from org",
			description: s.addedMemberOrganisationDescription,
			signer:      signer,
			changes: func(org *Organisation) *OrganisationChanges {
				changes := emptyOrganisationChanges()
				changes.MembersAdded[s.member3Key] = &protobuf.OrganisationMember{}
				changes.ChatsModified[testChatID1] = &OrganisationChatChanges{
					MembersAdded:   make(map[string]*protobuf.OrganisationMember),
					MembersRemoved: make(map[string]*protobuf.OrganisationMember),
				}
				changes.ChatsModified[testChatID1].MembersAdded[s.member3Key] = &protobuf.OrganisationMember{}

				return changes
			},
			err: nil,
		},
		{
			name:        "chat added to org",
			description: s.addedChatOrganisationDescription,
			signer:      signer,
			changes: func(org *Organisation) *OrganisationChanges {
				changes := emptyOrganisationChanges()
				changes.MembersAdded[s.member3Key] = &protobuf.OrganisationMember{}
				changes.ChatsAdded[testChatID2] = &protobuf.OrganisationChat{Members: make(map[string]*protobuf.OrganisationMember)}
				changes.ChatsAdded[testChatID2].Members[s.member3Key] = &protobuf.OrganisationMember{}

				return changes
			},
			err: nil,
		},
		{
			name:        "chat removed from the org",
			description: s.removedChatOrganisationDescription,
			signer:      signer,
			changes: func(org *Organisation) *OrganisationChanges {
				changes := emptyOrganisationChanges()
				changes.ChatsRemoved[testChatID1] = org.config.OrganisationDescription.Chats[testChatID1]

				return changes
			},
			err: nil,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			org := s.buildOrganisation(signer)
			expectedChanges := tc.changes(org)
			actualChanges, err := org.HandleOrganisationDescription(tc.signer, tc.description(org))
			s.Require().Equal(tc.err, err)
			s.Require().Equal(expectedChanges, actualChanges)
		})
	}
}

func (s *OrganisationSuite) emptyOrganisationDescription() *protobuf.OrganisationDescription {
	return &protobuf.OrganisationDescription{
		Permissions: &protobuf.OrganisationPermissions{},
	}

}

func (s *OrganisationSuite) emptyOrganisationDescriptionWithChat() *protobuf.OrganisationDescription {
	desc := &protobuf.OrganisationDescription{
		Chats:       make(map[string]*protobuf.OrganisationChat),
		Permissions: &protobuf.OrganisationPermissions{},
	}

	desc.Chats[testChatID1] = &protobuf.OrganisationChat{Permissions: &protobuf.OrganisationPermissions{}}

	return desc

}

func (s *OrganisationSuite) configOnRequest() Config {
	description := s.emptyOrganisationDescription()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configInvitationOnly() Config {
	description := s.emptyOrganisationDescription()
	description.Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configNoMembershipOrgNoMembershipChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configNoMembershipOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configInvitationOnlyOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configNoMembershipOrgOnRequestChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configOnRequestOrgOnRequestChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configOnRequestOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configChatENSOnly() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.EnsOnly = true
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configENSOnly() Config {
	description := s.emptyOrganisationDescription()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Permissions.EnsOnly = true
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) config() Config {
	config := s.configOnRequestOrgInvitationOnlyChat()
	return config
}

func (s *OrganisationSuite) buildOrganisation(owner *ecdsa.PublicKey) *Organisation {

	config := s.config()
	config.ID = owner
	config.OrganisationDescription.Clock = 1
	config.OrganisationDescription.Members = make(map[string]*protobuf.OrganisationMember)
	config.OrganisationDescription.Members[s.member1Key] = &protobuf.OrganisationMember{}
	config.OrganisationDescription.Members[s.member2Key] = &protobuf.OrganisationMember{}
	config.OrganisationDescription.Chats[testChatID1].Members = make(map[string]*protobuf.OrganisationMember)
	config.OrganisationDescription.Chats[testChatID1].Members[s.member1Key] = &protobuf.OrganisationMember{}

	org := New(config)
	return org
}

func (s *OrganisationSuite) identicalOrganisationDescription(org *Organisation) *protobuf.OrganisationDescription {
	description := proto.Clone(org.config.OrganisationDescription).(*protobuf.OrganisationDescription)
	description.Clock++
	return description
}

func (s *OrganisationSuite) oldOrganisationDescription(org *Organisation) *protobuf.OrganisationDescription {
	description := proto.Clone(org.config.OrganisationDescription).(*protobuf.OrganisationDescription)
	description.Clock--
	delete(description.Members, s.member1Key)
	delete(description.Chats[testChatID1].Members, s.member1Key)
	return description
}

func (s *OrganisationSuite) removedMemberOrganisationDescription(org *Organisation) *protobuf.OrganisationDescription {
	description := proto.Clone(org.config.OrganisationDescription).(*protobuf.OrganisationDescription)
	description.Clock++
	delete(description.Members, s.member1Key)
	delete(description.Chats[testChatID1].Members, s.member1Key)
	return description
}

func (s *OrganisationSuite) addedMemberOrganisationDescription(org *Organisation) *protobuf.OrganisationDescription {
	description := proto.Clone(org.config.OrganisationDescription).(*protobuf.OrganisationDescription)
	description.Clock++
	description.Members[s.member3Key] = &protobuf.OrganisationMember{}
	description.Chats[testChatID1].Members[s.member3Key] = &protobuf.OrganisationMember{}

	return description
}

func (s *OrganisationSuite) addedChatOrganisationDescription(org *Organisation) *protobuf.OrganisationDescription {
	description := proto.Clone(org.config.OrganisationDescription).(*protobuf.OrganisationDescription)
	description.Clock++
	description.Members[s.member3Key] = &protobuf.OrganisationMember{}
	description.Chats[testChatID2] = &protobuf.OrganisationChat{Members: make(map[string]*protobuf.OrganisationMember)}
	description.Chats[testChatID2].Members[s.member3Key] = &protobuf.OrganisationMember{}

	return description
}

func (s *OrganisationSuite) removedChatOrganisationDescription(org *Organisation) *protobuf.OrganisationDescription {
	description := proto.Clone(org.config.OrganisationDescription).(*protobuf.OrganisationDescription)
	description.Clock++
	delete(description.Chats, testChatID1)

	return description
}
