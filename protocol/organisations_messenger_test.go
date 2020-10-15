package protocol

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	gethbridge "github.com/status-im/status-go/eth-node/bridge/geth"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/protobuf"
	"github.com/status-im/status-go/protocol/tt"
	"github.com/status-im/status-go/waku"
)

func TestMessengerOrganisationsSuite(t *testing.T) {
	suite.Run(t, new(MessengerOrganisationsSuite))
}

type MessengerOrganisationsSuite struct {
	suite.Suite
	bob   *Messenger
	alice *Messenger
	// If one wants to send messages between different instances of Messenger,
	// a single Waku service should be shared.
	shh    types.Waku
	logger *zap.Logger
}

func (s *MessengerOrganisationsSuite) SetupTest() {
	s.logger = tt.MustCreateTestLogger()

	config := waku.DefaultConfig
	config.MinimumAcceptedPoW = 0
	shh := waku.New(&config, s.logger)
	s.shh = gethbridge.NewGethWakuWrapper(shh)
	s.Require().NoError(shh.Start(nil))

	s.bob = s.newMessenger(s.shh)
	s.alice = s.newMessenger(s.shh)
	s.Require().NoError(s.bob.Start())
	s.Require().NoError(s.alice.Start())
}

func (s *MessengerOrganisationsSuite) TearDownTest() {
	s.Require().NoError(s.bob.Shutdown())
	s.Require().NoError(s.alice.Shutdown())
	_ = s.logger.Sync()
}

func (s *MessengerOrganisationsSuite) newMessengerWithOptions(shh types.Waku, privateKey *ecdsa.PrivateKey, options []Option) *Messenger {
	m, err := NewMessenger(
		privateKey,
		&testNode{shh: shh},
		uuid.New().String(),
		options...,
	)
	s.Require().NoError(err)

	err = m.Init()
	s.Require().NoError(err)

	return m
}

func (s *MessengerOrganisationsSuite) newMessengerWithKey(shh types.Waku, privateKey *ecdsa.PrivateKey) *Messenger {
	tmpFile, err := ioutil.TempFile("", "")
	s.Require().NoError(err)

	options := []Option{
		WithCustomLogger(s.logger),
		WithMessagesPersistenceEnabled(),
		WithDatabaseConfig(tmpFile.Name(), ""),
		WithDatasync(),
	}
	return s.newMessengerWithOptions(shh, privateKey, options)
}

func (s *MessengerOrganisationsSuite) newMessenger(shh types.Waku) *Messenger {
	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	return s.newMessengerWithKey(s.shh, privateKey)
}

func (s *MessengerOrganisationsSuite) TestRetrieveOrganisation() {
	alice := s.newMessenger(s.shh)

	description := &protobuf.OrganisationDescription{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status",
			Description: "status organisation description",
		},
	}

	response, err := s.bob.CreateOrganisation(description)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)
	organisation := response.Organisations[0]

	// Send an organisation message
	chat := CreateOneToOneChat(common.PubkeyToHex(&alice.identity.PublicKey), &alice.identity.PublicKey, s.alice.transport)

	inputMessage := &common.Message{}
	inputMessage.ChatId = chat.ID
	inputMessage.Text = "some text"
	inputMessage.OrganisationID = organisation.IDString()

	err = s.bob.SaveChat(&chat)
	s.NoError(err)
	_, err = s.bob.SendChatMessage(context.Background(), inputMessage)
	s.NoError(err)

	// Pull message and make sure org is received
	err = tt.RetryWithBackOff(func() error {
		response, err = alice.RetrieveAll()
		if err != nil {
			return err
		}
		if len(response.Organisations) == 0 {
			return errors.New("organisation not received")
		}
		return nil
	})

	s.Require().NoError(err)
	organisations, err := alice.Organisations()
	s.Require().NoError(err)
	s.Require().Len(organisations, 1)
	s.Require().Len(response.Organisations, 1)
	s.Require().Len(response.Messages, 1)
	s.Require().Equal(organisation.IDString(), response.Messages[0].OrganisationID)
}

func (s *MessengerOrganisationsSuite) TestJoinOrganisation() {
	// start alice and enable sending push notifications
	s.Require().NoError(s.alice.Start())

	description := &protobuf.OrganisationDescription{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status",
			Description: "status organisation description",
		},
	}

	// Create an organisation chat
	response, err := s.bob.CreateOrganisation(description)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)

	organisation := response.Organisations[0]

	orgChat := &protobuf.OrganisationChat{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status-core",
			Description: "status-core organisation chat",
		},
	}
	response, err = s.bob.CreateOrganisationChat(organisation.IDString(), orgChat)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)
	s.Require().Len(response.Chats, 1)

	createdChat := response.Chats[0]
	s.Require().Equal(organisation.IDString(), createdChat.OrganisationID)
	s.Require().Equal(orgChat.Identity.DisplayName, createdChat.Name)
	s.Require().NotEmpty(createdChat.ID)
	s.Require().Equal(ChatTypeOrganisationChat, createdChat.ChatType)
	s.Require().True(createdChat.Active)
	s.Require().NotEmpty(createdChat.Timestamp)
	s.Require().True(strings.HasPrefix(createdChat.ID, organisation.IDString()))

	// Make sure the changes are reflect in the organisation
	organisation = response.Organisations[0]
	chats := organisation.Chats()
	s.Require().Len(chats, 1)

	// Send an organisation message
	chat := CreateOneToOneChat(common.PubkeyToHex(&s.alice.identity.PublicKey), &s.alice.identity.PublicKey, s.bob.transport)

	inputMessage := &common.Message{}
	inputMessage.ChatId = chat.ID
	inputMessage.Text = "some text"
	inputMessage.OrganisationID = organisation.IDString()

	err = s.bob.SaveChat(&chat)
	s.NoError(err)
	_, err = s.bob.SendChatMessage(context.Background(), inputMessage)
	s.NoError(err)

	// Pull message and make sure org is received
	err = tt.RetryWithBackOff(func() error {
		response, err = s.alice.RetrieveAll()
		if err != nil {
			return err
		}
		if len(response.Organisations) == 0 {
			return errors.New("organisation not received")
		}
		return nil
	})

	s.Require().NoError(err)
	organisations, err := s.alice.Organisations()
	s.Require().NoError(err)
	s.Require().Len(organisations, 1)
	s.Require().Len(response.Organisations, 1)
	s.Require().Len(response.Messages, 1)
	s.Require().Equal(organisation.IDString(), response.Messages[0].OrganisationID)

	// We join the org
	response, err = s.alice.JoinOrganisation(organisation.IDString())
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)
	s.Require().True(response.Organisations[0].Joined())
	s.Require().Len(response.Chats, 1)

	// The chat should be created
	createdChat = response.Chats[0]
	s.Require().Equal(organisation.IDString(), createdChat.OrganisationID)
	s.Require().Equal(orgChat.Identity.DisplayName, createdChat.Name)
	s.Require().NotEmpty(createdChat.ID)
	s.Require().Equal(ChatTypeOrganisationChat, createdChat.ChatType)
	s.Require().True(createdChat.Active)
	s.Require().NotEmpty(createdChat.Timestamp)
	s.Require().True(strings.HasPrefix(createdChat.ID, organisation.IDString()))

	// Create another org chat
	orgChat = &protobuf.OrganisationChat{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status-core-ui",
			Description: "status-core-ui organisation chat",
		},
	}
	response, err = s.bob.CreateOrganisationChat(organisation.IDString(), orgChat)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)
	s.Require().Len(response.Chats, 1)

	// Pull message, this time it should be received as advertised automatically
	err = tt.RetryWithBackOff(func() error {
		response, err = s.alice.RetrieveAll()
		if err != nil {
			return err
		}
		if len(response.Organisations) == 0 {
			return errors.New("organisation not received")
		}
		return nil
	})

	s.Require().NoError(err)
	organisations, err = s.alice.Organisations()
	s.Require().NoError(err)
	s.Require().Len(organisations, 1)
	s.Require().Len(response.Organisations, 1)
	s.Require().Len(response.Chats, 1)

	// The chat should be created
	createdChat = response.Chats[0]
	s.Require().Equal(organisation.IDString(), createdChat.OrganisationID)
	s.Require().Equal(orgChat.Identity.DisplayName, createdChat.Name)
	s.Require().NotEmpty(createdChat.ID)
	s.Require().Equal(ChatTypeOrganisationChat, createdChat.ChatType)
	s.Require().True(createdChat.Active)
	s.Require().NotEmpty(createdChat.Timestamp)
	s.Require().True(strings.HasPrefix(createdChat.ID, organisation.IDString()))

	// We leave the org
	response, err = s.alice.LeaveOrganisation(organisation.IDString())
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)
	s.Require().False(response.Organisations[0].Joined())
	s.Require().Len(response.RemovedChats, 2)
}

func (s *MessengerOrganisationsSuite) TestInviteUserToOrganisation() {
	description := &protobuf.OrganisationDescription{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status",
			Description: "status organisation description",
		},
	}

	// Create an organisation chat
	response, err := s.bob.CreateOrganisation(description)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)

	organisation := response.Organisations[0]

	response, err = s.bob.InviteUserToOrganisation(organisation.IDString(), common.PubkeyToHex(&s.alice.identity.PublicKey))
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)

	organisation = response.Organisations[0]
	s.Require().True(organisation.HasMember(&s.alice.identity.PublicKey))

	// Pull message and make sure org is received
	err = tt.RetryWithBackOff(func() error {
		response, err = s.alice.RetrieveAll()
		if err != nil {
			return err
		}
		if len(response.Organisations) == 0 {
			return errors.New("organisation not received")
		}
		return nil
	})

	s.Require().NoError(err)
	organisations, err := s.alice.Organisations()
	s.Require().NoError(err)
	s.Require().Len(organisations, 1)
	s.Require().Len(response.Organisations, 1)

	organisation = response.Organisations[0]
	s.Require().True(organisation.HasMember(&s.alice.identity.PublicKey))
}

func (s *MessengerOrganisationsSuite) TestPostToOrganisationChat() {
	description := &protobuf.OrganisationDescription{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_INVITATION_ONLY,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status",
			Description: "status organisation description",
		},
	}

	// Create an organisation chat
	response, err := s.bob.CreateOrganisation(description)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)

	organisation := response.Organisations[0]

	// Create chat
	orgChat := &protobuf.OrganisationChat{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status-core",
			Description: "status-core organisation chat",
		},
	}

	response, err = s.bob.CreateOrganisationChat(organisation.IDString(), orgChat)
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)
	s.Require().Len(response.Chats, 1)

	response, err = s.bob.InviteUserToOrganisation(organisation.IDString(), common.PubkeyToHex(&s.alice.identity.PublicKey))
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)

	organisation = response.Organisations[0]
	s.Require().True(organisation.HasMember(&s.alice.identity.PublicKey))

	// Pull message and make sure org is received
	err = tt.RetryWithBackOff(func() error {
		response, err = s.alice.RetrieveAll()
		if err != nil {
			return err
		}
		if len(response.Organisations) == 0 {
			return errors.New("organisation not received")
		}
		return nil
	})

	s.Require().NoError(err)
	organisations, err := s.alice.Organisations()
	s.Require().NoError(err)
	s.Require().Len(organisations, 1)
	s.Require().Len(response.Organisations, 1)

	// We join the org
	response, err = s.alice.JoinOrganisation(organisation.IDString())
	s.Require().NoError(err)
	s.Require().NotNil(response)
	s.Require().Len(response.Organisations, 1)
	s.Require().True(response.Organisations[0].Joined())
	s.Require().Len(response.Chats, 1)
	s.Require().Len(response.Filters, 2)

	var orgFilterFound bool
	var chatFilterFound bool
	for _, f := range response.Filters {
		orgFilterFound = orgFilterFound || f.ChatID == response.Organisations[0].IDString()
		chatFilterFound = chatFilterFound || f.ChatID == response.Chats[0].ID
	}
	// Make sure an organisation filter has been created
	s.Require().True(orgFilterFound)
	// Make sure the chat filter has been created
	s.Require().True(chatFilterFound)

	chatID := response.Chats[0].ID
	inputMessage := &common.Message{}
	inputMessage.ChatId = chatID
	inputMessage.ContentType = protobuf.ChatMessage_TEXT_PLAIN
	inputMessage.Text = "some text"

	_, err = s.alice.SendChatMessage(context.Background(), inputMessage)
	s.NoError(err)

	// Pull message and make sure org is received
	err = tt.RetryWithBackOff(func() error {
		response, err = s.bob.RetrieveAll()
		if err != nil {
			return err
		}
		if len(response.Messages) == 0 {
			return errors.New("message not received")
		}
		return nil
	})

	s.Require().NoError(err)
	s.Require().Len(response.Messages, 1)
	s.Require().Len(response.Chats, 1)
	s.Require().Equal(chatID, response.Chats[0].ID)
}
