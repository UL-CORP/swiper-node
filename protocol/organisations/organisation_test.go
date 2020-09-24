package organisations

import (
	"crypto/ecdsa"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/protocol/protobuf"
)

func TestOrganisationSuite(t *testing.T) {
	suite.Run(t, new(OrganisationSuite))
}

const testChatID = "chat-id"

type OrganisationSuite struct {
	suite.Suite

	identity       *ecdsa.PrivateKey
	organisationID []byte
}

func (s *OrganisationSuite) SetupTest() {
	identity, err := crypto.GenerateKey()
	s.Require().NoError(err)
	s.identity = identity
	s.organisationID = crypto.CompressPubkey(&identity.PublicKey)
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
		ChatId:         testChatID,
	}

	requestWithoutENS := &protobuf.OrganisationRequestJoin{
		OrganisationId: s.organisationID,
	}

	requestWithChatWithoutENS := &protobuf.OrganisationRequestJoin{
		OrganisationId: s.organisationID,
		ChatId:         testChatID,
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

func (s *OrganisationSuite) emptyOrganisationDescription() *protobuf.OrganisationDescription {
	return &protobuf.OrganisationDescription{
		Permissions: &protobuf.OrganisationPermissions{},
	}

}

func (s *OrganisationSuite) emptyOrganisationDescriptionWithChat() *protobuf.OrganisationDescription {
	return &protobuf.OrganisationDescription{
		Chats: []*protobuf.OrganisationChat{
			{
				ChatId:      testChatID,
				Permissions: &protobuf.OrganisationPermissions{},
			},
		},
		Permissions: &protobuf.OrganisationPermissions{},
	}

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
	description.Chats[0].Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configNoMembershipOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[0].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configInvitationOnlyOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	description.Chats[0].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configNoMembershipOrgOnRequestChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_NO_MEMBERSHIP
	description.Chats[0].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configOnRequestOrgOnRequestChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[0].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configOnRequestOrgInvitationOnlyChat() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[0].Permissions.Access = protobuf.OrganisationPermissions_INVITATION_ONLY
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configChatENSOnly() Config {
	description := s.emptyOrganisationDescriptionWithChat()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[0].Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Chats[0].Permissions.EnsOnly = true
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}

func (s *OrganisationSuite) configENSOnly() Config {
	description := s.emptyOrganisationDescription()
	description.Permissions.Access = protobuf.OrganisationPermissions_ON_REQUEST
	description.Permissions.EnsOnly = true
	return Config{OrganisationDescription: description, PrivateKey: s.identity}
}
