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

func (s *OrganisationSuite) TestInviteUserToOrg() {
	newMember, err := crypto.GenerateKey()
	s.Require().NoError(err)

	org := s.buildOrganisation(&s.identity.PublicKey)
	org.config.PrivateKey = nil
	// Not an admin
	_, err = org.InviteUserToOrg(&s.member2.PublicKey)
	s.Require().Equal(ErrNotAdmin, err)

	// Add admin to organisation
	org.config.PrivateKey = s.identity

	response, err := org.InviteUserToOrg(&newMember.PublicKey)
	s.Require().Nil(err)
	s.Require().NotNil(response)

	// Check member has been added
	s.Require().True(org.HasMember(&newMember.PublicKey))

	// Check member has been added to response
	s.Require().NotNil(response.OrganisationDescription)

	metadata := &protobuf.ApplicationMetadataMessage{}
	description := &protobuf.OrganisationDescription{}

	s.Require().NoError(proto.Unmarshal(response.OrganisationDescription, metadata))
	s.Require().NoError(proto.Unmarshal(metadata.Payload, description))

	_, ok := description.Members[common.PubkeyToHex(&newMember.PublicKey)]
	s.Require().True(ok)

	// Check grant validates
	s.Require().NotNil(org.config.ID)
	s.Require().NotNil(response.Grant)

	grant, err := org.VerifyGrantSignature(response.Grant)
	s.Require().NoError(err)
	s.Require().NotNil(grant)
}

func (s *OrganisationSuite) TestCreateChat() {
	newChatID := "new-chat-id"
	org := s.buildOrganisation(&s.identity.PublicKey)
	org.config.PrivateKey = nil

	identity := &protobuf.ChatIdentity{
		DisplayName: "new-chat-display-name",
		Description: "new-chat-description",
	}
	permissions := &protobuf.OrganisationPermissions{
		Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
	}

	_, err := org.CreateChat(newChatID, &protobuf.OrganisationChat{
		Identity:    identity,
		Permissions: permissions,
	})

	s.Require().Equal(ErrNotAdmin, err)

	org.config.PrivateKey = s.identity

	changes, err := org.CreateChat(newChatID, &protobuf.OrganisationChat{
		Identity:    identity,
		Permissions: permissions,
	})

	description := org.config.OrganisationDescription

	s.Require().NoError(err)
	s.Require().NotNil(description)

	s.Require().NotNil(description.Chats[newChatID])
	s.Require().NotEmpty(description.Chats[newChatID].Clock)
	s.Require().Equal(permissions, description.Chats[newChatID].Permissions)
	s.Require().Equal(identity, description.Chats[newChatID].Identity)
	s.Require().Equal(description.Clock, description.Chats[newChatID].Clock)

	s.Require().NotNil(changes)
	s.Require().NotNil(changes.ChatsAdded[newChatID])
}

func (s *OrganisationSuite) TestDeleteChat() {
	org := s.buildOrganisation(&s.identity.PublicKey)
	org.config.PrivateKey = nil

	_, err := org.DeleteChat(testChatID1)
	s.Require().Equal(ErrNotAdmin, err)

	org.config.PrivateKey = s.identity

	description, err := org.DeleteChat(testChatID1)
	s.Require().NoError(err)
	s.Require().NotNil(description)

	s.Require().Nil(description.Chats[testChatID1])
	s.Require().Equal(uint64(2), description.Clock)
}

func (s *OrganisationSuite) TestInviteUserToChat() {
	newMember, err := crypto.GenerateKey()
	s.Require().NoError(err)

	org := s.buildOrganisation(&s.identity.PublicKey)
	org.config.PrivateKey = nil
	// Not an admin
	_, err = org.InviteUserToChat(&s.member2.PublicKey, testChatID1)
	s.Require().Equal(ErrNotAdmin, err)

	// Add admin to organisation
	org.config.PrivateKey = s.identity

	response, err := org.InviteUserToChat(&newMember.PublicKey, testChatID1)
	s.Require().Nil(err)
	s.Require().NotNil(response)

	// Check member has been added
	s.Require().True(org.HasMember(&newMember.PublicKey))
	s.Require().True(org.IsMemberInChat(&newMember.PublicKey, testChatID1))

	// Check member has been added to response
	s.Require().NotNil(response.OrganisationDescription)

	metadata := &protobuf.ApplicationMetadataMessage{}
	description := &protobuf.OrganisationDescription{}

	s.Require().NoError(proto.Unmarshal(response.OrganisationDescription, metadata))
	s.Require().NoError(proto.Unmarshal(metadata.Payload, description))

	_, ok := description.Members[common.PubkeyToHex(&newMember.PublicKey)]
	s.Require().True(ok)

	_, ok = description.Chats[testChatID1].Members[common.PubkeyToHex(&newMember.PublicKey)]
	s.Require().True(ok)

	s.Require().Equal(testChatID1, response.ChatId)

	// Check grant validates
	s.Require().NotNil(org.config.ID)
	s.Require().NotNil(response.Grant)

	grant, err := org.VerifyGrantSignature(response.Grant)
	s.Require().NoError(err)
	s.Require().NotNil(grant)
	s.Require().Equal(testChatID1, grant.ChatId)
}

func (s *OrganisationSuite) TestRemoveUserFromChat() {
	org := s.buildOrganisation(&s.identity.PublicKey)
	org.config.PrivateKey = nil
	// Not an admin
	_, err := org.RemoveUserFromOrg(&s.member1.PublicKey)
	s.Require().Equal(ErrNotAdmin, err)

	// Add admin to organisation
	org.config.PrivateKey = s.identity

	actualOrganisation, err := org.RemoveUserFromChat(&s.member1.PublicKey, testChatID1)
	s.Require().Nil(err)
	s.Require().NotNil(actualOrganisation)

	// Check member has not been removed
	s.Require().True(org.HasMember(&s.member1.PublicKey))

	// Check member has not been removed from org
	_, ok := actualOrganisation.Members[common.PubkeyToHex(&s.member1.PublicKey)]
	s.Require().True(ok)

	// Check member has been removed from chat
	_, ok = actualOrganisation.Chats[testChatID1].Members[common.PubkeyToHex(&s.member1.PublicKey)]
	s.Require().False(ok)
}

func (s *OrganisationSuite) TestRemoveUserFormOrg() {
	org := s.buildOrganisation(&s.identity.PublicKey)
	org.config.PrivateKey = nil
	// Not an admin
	_, err := org.RemoveUserFromOrg(&s.member1.PublicKey)
	s.Require().Equal(ErrNotAdmin, err)

	// Add admin to organisation
	org.config.PrivateKey = s.identity

	actualOrganisation, err := org.RemoveUserFromOrg(&s.member1.PublicKey)
	s.Require().Nil(err)
	s.Require().NotNil(actualOrganisation)

	// Check member has been removed
	s.Require().False(org.HasMember(&s.member1.PublicKey))

	// Check member has been removed from org
	_, ok := actualOrganisation.Members[common.PubkeyToHex(&s.member1.PublicKey)]
	s.Require().False(ok)

	// Check member has been removed from chat
	_, ok = actualOrganisation.Chats[testChatID1].Members[common.PubkeyToHex(&s.member1.PublicKey)]
	s.Require().False(ok)
}

func (s *OrganisationSuite) TestAcceptRequestToJoin() {
	// WHAT TO DO WITH ENS
	// TEST CASE 1: Not an admin
	// TEST CASE 2: No request to join
	// TEST CASE 3: Valid
}

func (s *OrganisationSuite) TestDeclineRequestToJoin() {
	// TEST CASE 1: Not an admin
	// TEST CASE 2: No request to join
	// TEST CASE 3: Valid
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
	// NO_MEMBERHSIP - NO_MEMBERSHIP -> Error -> Anyone can join org, chat is read/write for anyone
	// NO_MEMBRISHIP - INVITATION_ONLY -> Error -> Anyone can join org, chat is invitation only
	// NO_MEMBERSHIP - ON_REQUEST -> Success -> Anyone can join org, chat is on request and needs approval
	// INVITATION_ONLY - NO_MEMBERSHIP -> TODO -> Org is invitation only, chat is read-write for members
	// INVITATION_ONLY - INVITATION_ONLY -> Error -> Org is invitation only, chat is invitation only
	// INVITATION_ONLY - ON_REQUEST -> TODO -> Error -> Org is invitation only, member of the org need to request access for chat
	// ON_REQUEST - NO_MEMBRERSHIP -> TODO -> Error -> Org is on request, chat is read write for members
	// ON_REQUEST - INVITATION_ONLY -> Error -> Org is on request, chat is invitation only for members
	// ON_REQUEST - ON_REQUEST -> Fine -> Org is on request, chat is on request

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

func (s *OrganisationSuite) TestHandleOrganisationDescription() {
	key, err := crypto.GenerateKey()
	s.Require().NoError(err)

	signer := &key.PublicKey

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
				changes.ChatsAdded[testChatID2] = &protobuf.OrganisationChat{Permissions: &protobuf.OrganisationPermissions{Access: protobuf.OrganisationPermissions_INVITATION_ONLY}, Members: make(map[string]*protobuf.OrganisationMember)}
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
			org.Join()
			expectedChanges := tc.changes(org)
			actualChanges, err := org.HandleOrganisationDescription(tc.signer, tc.description(org), []byte{0x01})
			s.Require().Equal(tc.err, err)
			s.Require().Equal(expectedChanges, actualChanges)
		})
	}
}

func (s *OrganisationSuite) TestValidateOrganisationDescription() {

	testCases := []struct {
		name        string
		description *protobuf.OrganisationDescription
		err         error
	}{
		{
			name:        "valid",
			description: s.buildOrganisationDescription(),
			err:         nil,
		},
		{
			name: "empty description",
			err:  ErrInvalidOrganisationDescription,
		},
		{
			name:        "empty org permissions",
			description: s.emptyPermissionsOrganisationDescription(),
			err:         ErrInvalidOrganisationDescriptionNoOrgPermissions,
		},
		{
			name:        "empty chat permissions",
			description: s.emptyChatPermissionsOrganisationDescription(),
			err:         ErrInvalidOrganisationDescriptionNoChatPermissions,
		},
		{
			name:        "unknown org permissions",
			description: s.unknownOrgPermissionsOrganisationDescription(),
			err:         ErrInvalidOrganisationDescriptionUnknownOrgAccess,
		},
		{
			name:        "unknown chat permissions",
			description: s.unknownChatPermissionsOrganisationDescription(),
			err:         ErrInvalidOrganisationDescriptionUnknownChatAccess,
		},
		{
			name:        "member in chat but not in org",
			description: s.memberInChatNotInOrgOrganisationDescription(),
			err:         ErrInvalidOrganisationDescriptionMemberInChatButNotInOrg,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			err := ValidateOrganisationDescription(tc.description)
			s.Require().Equal(tc.err, err)
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
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configInvitationOnly() Config {
	description := s.emptyOrganisationDescription()
	description.Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configNoMembershipOrgNoMembershipChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}

}

func (s *OrganisationSuite) configNoMembershipOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configInvitationOnlyOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configNoMembershipOrgOnRequestChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configOnRequestOrgOnRequestChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configOnRequestOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configChatENSOnly() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[testChatID1].Permissions.EnsOnly = true
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) configENSOnly() Config {
	description := s.emptyOrganisationDescription()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Permissions.EnsOnly = true
	return Config{
		ID:                      &s.identity.PublicKey,
		OrganisationDescription: description,
		PrivateKey:              s.identity,
	}
}

func (s *OrganisationSuite) config() Config {
	config := s.configOnRequestOrgInvitationOnlyChat()
	return config
}

func (s *OrganisationSuite) buildOrganisationDescription() *protobuf.OrganisationDescription {
	config := s.configOnRequestOrgInvitationOnlyChat()
	desc := config.OrganisationDescription
	desc.Clock = 1
	desc.Members = make(map[string]*protobuf.OrganisationMember)
	desc.Members[s.member1Key] = &protobuf.OrganisationMember{}
	desc.Members[s.member2Key] = &protobuf.OrganisationMember{}
	desc.Chats[testChatID1].Members = make(map[string]*protobuf.OrganisationMember)
	desc.Chats[testChatID1].Members[s.member1Key] = &protobuf.OrganisationMember{}
	return desc
}

func (s *OrganisationSuite) emptyPermissionsOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Permissions = nil
	return desc
}

func (s *OrganisationSuite) emptyChatPermissionsOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Chats[testChatID1].Permissions = nil
	return desc
}

func (s *OrganisationSuite) unknownOrgPermissionsOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Permissions.Access = protobuf.OrganisationPermissions_UNKNOWN_ACCESS
	return desc
}

func (s *OrganisationSuite) unknownChatPermissionsOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_UNKNOWN_ACCESS
	return desc
}

func (s *OrganisationSuite) memberInChatNotInOrgOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Chats[testChatID1].Members[s.member3Key] = &protobuf.OrganisationMember{}
	return desc
}

func (s *OrganisationSuite) invitationOnlyOrgNoMembershipChatOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	desc.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	return desc
}

func (s *OrganisationSuite) invitationOnlyOrgOnRequestChatOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	desc.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return desc
}

func (s *OrganisationSuite) onRequestOrgNoMembershipChatOrganisationDescription() *protobuf.OrganisationDescription {
	desc := s.buildOrganisationDescription()
	desc.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	desc.Chats[testChatID1].Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	return desc
}

func (s *OrganisationSuite) buildOrganisation(owner *ecdsa.PublicKey) *Organisation {

	config := s.config()
	config.ID = owner
	config.OrganisationDescription = s.buildOrganisationDescription()

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
	description.Chats[testChatID2] = &protobuf.OrganisationChat{Permissions: &protobuf.OrganisationPermissions{Access: protobuf.OrganisationPermissions_INVITATION_ONLY}, Members: make(map[string]*protobuf.OrganisationMember)}
	description.Chats[testChatID2].Members[s.member3Key] = &protobuf.OrganisationMember{}

	return description
}

func (s *OrganisationSuite) removedChatOrganisationDescription(org *Organisation) *protobuf.OrganisationDescription {
	description := proto.Clone(org.config.OrganisationDescription).(*protobuf.OrganisationDescription)
	description.Clock++
	delete(description.Chats, testChatID1)

	return description
}
