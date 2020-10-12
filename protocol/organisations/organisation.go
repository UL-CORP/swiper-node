package organisations

import (
	"bytes"
	"crypto/ecdsa"

	"github.com/golang/protobuf/proto"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/protobuf"
)

const signatureLength = 65

type Config struct {
	PrivateKey              *ecdsa.PrivateKey
	OrganisationDescription *protobuf.OrganisationDescription
	ID                      *ecdsa.PublicKey
}

type Organisation struct {
	Identity *protobuf.ChatMessageIdentity

	config *Config
}

func New(config Config) *Organisation {
	organisation := &Organisation{config: &config}
	organisation.initialize()
	return organisation
}

func (o *Organisation) initialize() {
	if o.config.OrganisationDescription == nil {
		o.config.OrganisationDescription = &protobuf.OrganisationDescription{}

	}
}

type OrganisationChatChanges struct {
	MembersAdded   map[string]*protobuf.OrganisationMember
	MembersRemoved map[string]*protobuf.OrganisationMember
}

type OrganisationChanges struct {
	MembersAdded   map[string]*protobuf.OrganisationMember
	MembersRemoved map[string]*protobuf.OrganisationMember

	ChatsRemoved  map[string]*protobuf.OrganisationChat
	ChatsAdded    map[string]*protobuf.OrganisationChat
	ChatsModified map[string]*OrganisationChatChanges
}

func emptyOrganisationChanges() *OrganisationChanges {
	return &OrganisationChanges{
		MembersAdded:   make(map[string]*protobuf.OrganisationMember),
		MembersRemoved: make(map[string]*protobuf.OrganisationMember),

		ChatsRemoved:  make(map[string]*protobuf.OrganisationChat),
		ChatsAdded:    make(map[string]*protobuf.OrganisationChat),
		ChatsModified: make(map[string]*OrganisationChatChanges),
	}
}

func (o *Organisation) InviteUserToOrg(pk *ecdsa.PublicKey) (*protobuf.OrganisationInvitation, error) {
	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}
	memberKey := common.PubkeyToHex(pk)

	if _, ok := o.config.OrganisationDescription.Members[memberKey]; !ok {
		o.config.OrganisationDescription.Members[memberKey] = &protobuf.OrganisationMember{}
	}

	response := &protobuf.OrganisationInvitation{Organisation: o.config.OrganisationDescription}
	grant, err := o.buildGrant(pk, "")
	if err != nil {
		return nil, err
	}
	response.Grant = grant

	return response, nil
}

func (o *Organisation) InviteUserToChat(pk *ecdsa.PublicKey, chatID string) (*protobuf.OrganisationInvitation, error) {
	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}
	memberKey := common.PubkeyToHex(pk)

	if _, ok := o.config.OrganisationDescription.Members[memberKey]; !ok {
		o.config.OrganisationDescription.Members[memberKey] = &protobuf.OrganisationMember{}
	}

	chat, ok := o.config.OrganisationDescription.Chats[chatID]
	if !ok {
		return nil, ErrChatNotFound
	}

	if chat.Members == nil {
		chat.Members = make(map[string]*protobuf.OrganisationMember)
	}
	chat.Members[memberKey] = &protobuf.OrganisationMember{}

	response := &protobuf.OrganisationInvitation{Organisation: o.config.OrganisationDescription}
	grant, err := o.buildGrant(pk, chatID)
	if err != nil {
		return nil, err
	}
	response.Grant = grant
	response.ChatId = chatID

	return response, nil
}

func (o *Organisation) HasMember(pk *ecdsa.PublicKey) bool {
	key := common.PubkeyToHex(pk)
	_, ok := o.config.OrganisationDescription.Members[key]
	return ok
}

func (o *Organisation) IsMemberInChat(pk *ecdsa.PublicKey, chatID string) bool {
	if !o.HasMember(pk) {
		return false
	}

	chat, ok := o.config.OrganisationDescription.Chats[chatID]
	if !ok {
		return false
	}

	key := common.PubkeyToHex(pk)
	_, ok = chat.Members[key]
	return ok
}

func (o *Organisation) RemoveUserFromChat(pk *ecdsa.PublicKey, chatID string) (*protobuf.OrganisationDescription, error) {
	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}
	if !o.HasMember(pk) {
		return o.config.OrganisationDescription, nil
	}

	chat, ok := o.config.OrganisationDescription.Chats[chatID]
	if !ok {
		return o.config.OrganisationDescription, nil
	}

	key := common.PubkeyToHex(pk)
	delete(chat.Members, key)

	return o.config.OrganisationDescription, nil
}

func (o *Organisation) RemoveUserFromOrg(pk *ecdsa.PublicKey) (*protobuf.OrganisationDescription, error) {
	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}
	if !o.HasMember(pk) {
		return o.config.OrganisationDescription, nil
	}
	key := common.PubkeyToHex(pk)

	// Remove from org
	delete(o.config.OrganisationDescription.Members, key)

	// Remove from chats
	for _, chat := range o.config.OrganisationDescription.Chats {
		delete(chat.Members, key)
	}

	return o.config.OrganisationDescription, nil
}

func (o *Organisation) AcceptRequestToJoin(pk *ecdsa.PublicKey) (*protobuf.OrganisationRequestJoinResponse, error) {
	return nil, nil
}

func (o *Organisation) DeclineRequestToJoin(pk *ecdsa.PublicKey) (*protobuf.OrganisationRequestJoinResponse, error) {
	return nil, nil
}

func (o *Organisation) HandleOrganisationDescription(signer *ecdsa.PublicKey, description *protobuf.OrganisationDescription) (*OrganisationChanges, error) {
	// TOOD: validate signer

	err := ValidateOrganisationDescription(description)
	if err != nil {
		return nil, err
	}

	response := emptyOrganisationChanges()

	if description.Clock <= o.config.OrganisationDescription.Clock {
		return response, nil
	}

	// Check for new members at the org level
	for pk, member := range description.Members {
		if _, ok := o.config.OrganisationDescription.Members[pk]; !ok {
			if response.MembersAdded == nil {
				response.MembersAdded = make(map[string]*protobuf.OrganisationMember)
			}
			response.MembersAdded[pk] = member
		}
	}

	// Check for removed members at the org level
	for pk, member := range o.config.OrganisationDescription.Members {
		if _, ok := description.Members[pk]; !ok {
			if response.MembersRemoved == nil {
				response.MembersRemoved = make(map[string]*protobuf.OrganisationMember)
			}
			response.MembersRemoved[pk] = member
		}
	}

	// check for removed chats
	for chatID, chat := range o.config.OrganisationDescription.Chats {
		if description.Chats == nil {
			description.Chats = make(map[string]*protobuf.OrganisationChat)
		}
		if _, ok := description.Chats[chatID]; !ok {
			if response.ChatsRemoved == nil {
				response.ChatsRemoved = make(map[string]*protobuf.OrganisationChat)
			}

			response.ChatsRemoved[chatID] = chat
		}
	}

	for chatID, chat := range description.Chats {
		if o.config.OrganisationDescription.Chats == nil {
			o.config.OrganisationDescription.Chats = make(map[string]*protobuf.OrganisationChat)
		}
		if _, ok := o.config.OrganisationDescription.Chats[chatID]; !ok {
			if response.ChatsAdded == nil {
				response.ChatsAdded = make(map[string]*protobuf.OrganisationChat)
			}

			response.ChatsAdded[chatID] = chat
		} else {
			// Check for members added
			for pk, member := range description.Chats[chatID].Members {
				if _, ok := o.config.OrganisationDescription.Chats[chatID].Members[pk]; !ok {
					if response.ChatsModified[chatID] == nil {
						response.ChatsModified[chatID] = &OrganisationChatChanges{
							MembersAdded:   make(map[string]*protobuf.OrganisationMember),
							MembersRemoved: make(map[string]*protobuf.OrganisationMember),
						}
					}

					response.ChatsModified[chatID].MembersAdded[pk] = member
				}
			}

			// check for members removed
			for pk, member := range o.config.OrganisationDescription.Chats[chatID].Members {
				if _, ok := description.Chats[chatID].Members[pk]; !ok {
					if response.ChatsModified[chatID] == nil {
						response.ChatsModified[chatID] = &OrganisationChatChanges{
							MembersAdded:   make(map[string]*protobuf.OrganisationMember),
							MembersRemoved: make(map[string]*protobuf.OrganisationMember),
						}
					}

					response.ChatsModified[chatID].MembersRemoved[pk] = member
				}
			}
		}
	}

	o.config.OrganisationDescription = description

	// store

	return response, nil
}

// HandleRequestJoin handles a request, checks that the right permissions are applied and returns an OrganisationRequestJoinResponse
func (o *Organisation) HandleRequestJoin(signer *ecdsa.PublicKey, request *protobuf.OrganisationRequestJoin) error {
	// If we are not admin, fuggetaboutit
	if !o.IsAdmin() {
		return ErrNotAdmin
	}

	// If the org is ens name only, then reject if not present
	if o.config.OrganisationDescription.Permissions.EnsOnly && len(request.EnsName) == 0 {
		return ErrCantRequestAccess
	}

	if len(request.ChatId) != 0 {
		return o.handleRequestJoinWithChatID(signer, request)
	}

	err := o.handleRequestJoinWithoutChatID(signer, request)
	if err != nil {
		return err
	}

	// Store request to join
	return nil
}

func (o *Organisation) IsAdmin() bool {
	return o.config.PrivateKey != nil
}

func (o *Organisation) handleRequestJoinWithChatID(signer *ecdsa.PublicKey, request *protobuf.OrganisationRequestJoin) error {
	var chat *protobuf.OrganisationChat
	chat, ok := o.config.OrganisationDescription.Chats[request.ChatId]

	if !ok {
		return ErrChatNotFound
	}

	// If chat is no permissions, access should not have been requested
	if chat.Permissions.Access != protobuf.OrganisationPermissions_ON_REQUEST {
		return ErrCantRequestAccess
	}

	if chat.Permissions.EnsOnly && len(request.EnsName) == 0 {
		return ErrCantRequestAccess
	}

	return nil
}

func (o *Organisation) handleRequestJoinWithoutChatID(signer *ecdsa.PublicKey, request *protobuf.OrganisationRequestJoin) error {

	// If they want access to the org only, check that the org is ON_REQUEST
	if o.config.OrganisationDescription.Permissions.Access != protobuf.OrganisationPermissions_ON_REQUEST {
		return ErrCantRequestAccess
	}

	return nil
}

func (o *Organisation) ID() []byte {
	return crypto.CompressPubkey(o.config.ID)
}
func (o *Organisation) VerifyGrantSignature(data []byte) (*protobuf.Grant, error) {
	if len(data) <= signatureLength {
		return nil, ErrInvalidGrant
	}
	signature := data[:signatureLength]
	payload := data[signatureLength:]
	grant := &protobuf.Grant{}
	err := proto.Unmarshal(payload, grant)
	if err != nil {
		return nil, err
	}

	if grant.Clock == 0 {
		return nil, ErrInvalidGrant
	}
	if grant.MemberId == nil {
		return nil, ErrInvalidGrant
	}
	if !bytes.Equal(grant.OrganisationId, o.ID()) {
		return nil, ErrInvalidGrant
	}

	extractedPublicKey, err := crypto.SigToPub(crypto.Keccak256(payload), signature)
	if err != nil {
		return nil, err
	}

	if !common.IsPubKeyEqual(o.config.ID, extractedPublicKey) {
		return nil, ErrInvalidGrant
	}

	return grant, nil
}

func (o *Organisation) buildGrant(key *ecdsa.PublicKey, chatID string) ([]byte, error) {
	grant := &protobuf.Grant{
		OrganisationId: o.ID(),
		MemberId:       crypto.CompressPubkey(key),
		ChatId:         chatID,
		Clock:          o.config.OrganisationDescription.Clock,
	}
	marshaledGrant, err := proto.Marshal(grant)
	if err != nil {
		return nil, err
	}

	signatureMaterial := crypto.Keccak256(marshaledGrant)

	signature, err := crypto.Sign(signatureMaterial, o.config.PrivateKey)
	if err != nil {
		return nil, err
	}

	return append(signature, marshaledGrant...), nil
}
