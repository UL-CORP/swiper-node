package organisations

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"sync"

	"github.com/golang/protobuf/proto"
	"go.uber.org/zap"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/protobuf"
	"github.com/status-im/status-go/protocol/v1"
)

const signatureLength = 65

type Config struct {
	PrivateKey                       *ecdsa.PrivateKey
	OrganisationDescription          *protobuf.OrganisationDescription
	MarshaledOrganisationDescription []byte
	ID                               *ecdsa.PublicKey
	Joined                           bool
	Logger                           *zap.Logger
}

type Organisation struct {
	config *Config
	mutex  sync.Mutex
}

func New(config Config) (*Organisation, error) {
	if config.Logger == nil {
		logger, err := zap.NewDevelopment()
		if err != nil {
			return nil, err
		}
		config.Logger = logger
	}

	organisation := &Organisation{config: &config}
	organisation.initialize()
	return organisation, nil
}

func (o *Organisation) MarshalJSON() ([]byte, error) {
	item := struct {
		ID                                string `json:"id"`
		*protobuf.OrganisationDescription `json:"description"`
		Admin                             bool `json:"admin"`
		Joined                            bool `json:"joined"`
	}{
		ID:                      o.IDString(),
		OrganisationDescription: o.config.OrganisationDescription,
		Admin:                   o.config.PrivateKey != nil,
		Joined:                  o.config.Joined,
	}
	return json.Marshal(item)
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

func (o *Organisation) CreateChat(chatID string, chat *protobuf.OrganisationChat) (*OrganisationChanges, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}

	err := validateOrganisationChat(o.config.OrganisationDescription, chat)
	if err != nil {
		return nil, err
	}

	if o.config.OrganisationDescription.Chats == nil {
		o.config.OrganisationDescription.Chats = make(map[string]*protobuf.OrganisationChat)
	}
	if _, ok := o.config.OrganisationDescription.Chats[chatID]; ok {
		return nil, ErrChatAlreadyExists
	}

	o.config.OrganisationDescription.Chats[chatID] = chat

	o.increaseClock()

	changes := emptyOrganisationChanges()
	changes.ChatsAdded[chatID] = chat
	return changes, nil
}

func (o *Organisation) DeleteChat(chatID string) (*protobuf.OrganisationDescription, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}

	if o.config.OrganisationDescription.Chats == nil {
		o.config.OrganisationDescription.Chats = make(map[string]*protobuf.OrganisationChat)
	}
	delete(o.config.OrganisationDescription.Chats, chatID)

	o.increaseClock()

	return o.config.OrganisationDescription, nil
}

func (o *Organisation) InviteUserToOrg(pk *ecdsa.PublicKey) (*protobuf.OrganisationInvitation, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}
	memberKey := common.PubkeyToHex(pk)

	if o.config.OrganisationDescription.Members == nil {
		o.config.OrganisationDescription.Members = make(map[string]*protobuf.OrganisationMember)
	}

	if _, ok := o.config.OrganisationDescription.Members[memberKey]; !ok {
		o.config.OrganisationDescription.Members[memberKey] = &protobuf.OrganisationMember{}
	}

	o.increaseClock()

	response := &protobuf.OrganisationInvitation{}
	marshaledOrganisation, err := o.toBytes()
	if err != nil {
		return nil, err
	}
	response.OrganisationDescription = marshaledOrganisation

	grant, err := o.buildGrant(pk, "")
	if err != nil {
		return nil, err
	}
	response.Grant = grant
	response.PublicKey = crypto.CompressPubkey(pk)

	return response, nil
}

func (o *Organisation) InviteUserToChat(pk *ecdsa.PublicKey, chatID string) (*protobuf.OrganisationInvitation, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

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

	o.increaseClock()

	response := &protobuf.OrganisationInvitation{}
	marshaledOrganisation, err := o.toBytes()
	if err != nil {
		return nil, err
	}
	response.OrganisationDescription = marshaledOrganisation

	grant, err := o.buildGrant(pk, chatID)
	if err != nil {
		return nil, err
	}
	response.Grant = grant
	response.ChatId = chatID

	return response, nil
}

func (o *Organisation) hasMember(pk *ecdsa.PublicKey) bool {

	key := common.PubkeyToHex(pk)
	_, ok := o.config.OrganisationDescription.Members[key]
	return ok
}

func (o *Organisation) HasMember(pk *ecdsa.PublicKey) bool {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.hasMember(pk)
}

func (o *Organisation) IsMemberInChat(pk *ecdsa.PublicKey, chatID string) bool {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if !o.hasMember(pk) {
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
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}
	if !o.hasMember(pk) {
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
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.config.PrivateKey == nil {
		return nil, ErrNotAdmin
	}
	if !o.hasMember(pk) {
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

func (o *Organisation) Join() {
	o.config.Joined = true
}

func (o *Organisation) Leave() {
	o.config.Joined = false
}

func (o *Organisation) Joined() bool {
	return o.config.Joined
}

func (o *Organisation) HandleOrganisationDescription(signer *ecdsa.PublicKey, description *protobuf.OrganisationDescription, rawMessage []byte) (*OrganisationChanges, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if !common.IsPubKeyEqual(o.config.ID, signer) {
		return nil, ErrNotAuthorized
	}

	err := ValidateOrganisationDescription(description)
	if err != nil {
		return nil, err
	}

	response := emptyOrganisationChanges()

	if description.Clock <= o.config.OrganisationDescription.Clock {
		return response, nil
	}

	// We only calculate changes if we joined the org, otherwise not interested
	if o.config.Joined {
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
	}

	o.config.OrganisationDescription = description
	o.config.MarshaledOrganisationDescription = rawMessage

	return response, nil
}

// HandleRequestJoin handles a request, checks that the right permissions are applied and returns an OrganisationRequestJoinResponse
func (o *Organisation) HandleRequestJoin(signer *ecdsa.PublicKey, request *protobuf.OrganisationRequestJoin) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

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

func (o *Organisation) IDString() string {
	return types.EncodeHex(o.ID())
}

func (o *Organisation) PrivateKey() *ecdsa.PrivateKey {
	return o.config.PrivateKey
}

func (o *Organisation) marshaledDescription() ([]byte, error) {
	return proto.Marshal(o.config.OrganisationDescription)
}

func (o *Organisation) MarshaledDescription() ([]byte, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.marshaledDescription()
}

func (o *Organisation) toBytes() ([]byte, error) {

	// This should not happen, as we can only serialize on our side if we
	// created the organisation
	if o.config.PrivateKey == nil && len(o.config.MarshaledOrganisationDescription) == 0 {
		return nil, ErrNotAdmin
	}

	// We are not admin, use the received serialized version
	if o.config.PrivateKey == nil {
		return o.config.MarshaledOrganisationDescription, nil
	}

	// serialize and sign
	payload, err := o.marshaledDescription()
	if err != nil {
		return nil, err
	}

	return protocol.WrapMessageV1(payload, protobuf.ApplicationMetadataMessage_ORGANISATION_DESCRIPTION, o.config.PrivateKey)
}

// ToBytes returns the organisation in a wrapped & signed protocol message
func (o *Organisation) ToBytes() ([]byte, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.toBytes()
}

func (o *Organisation) Chats() map[string]*protobuf.OrganisationChat {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	response := make(map[string]*protobuf.OrganisationChat)
	for k, v := range o.config.OrganisationDescription.Chats {
		response[k] = v
	}
	return response
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

func (o *Organisation) CanPost(pk *ecdsa.PublicKey, chatID string, grantBytes []byte) (bool, error) {
	if o.config.OrganisationDescription.Chats == nil {
		o.config.Logger.Debug("canPost, no-chats")
		return false, nil
	}

	chat, ok := o.config.OrganisationDescription.Chats[chatID]
	if !ok {
		o.config.Logger.Debug("canPost, no chat with id", zap.String("chat-id", chatID))
		return false, nil
	}

	// creator can always post
	if common.IsPubKeyEqual(pk, o.config.ID) {
		return true, nil
	}

	// If both the chat & the org have no permissions, the user is allowed to post
	if o.config.OrganisationDescription.Permissions.Access == protobuf.OrganisationPermissions_NO_MEMBERSHIP && chat.Permissions.Access == protobuf.OrganisationPermissions_NO_MEMBERSHIP {
		return true, nil
	}

	if chat.Permissions.Access != protobuf.OrganisationPermissions_NO_MEMBERSHIP {
		if chat.Members == nil {
			o.config.Logger.Debug("canPost, no members in chat", zap.String("chat-id", chatID))
			return false, nil
		}

		_, ok := chat.Members[common.PubkeyToHex(pk)]
		// If member, we stop here
		if ok {
			return true, nil
		}

		// If not a member, and not grant, we return
		if !ok && grantBytes == nil {
			o.config.Logger.Debug("canPost, not a member in chat", zap.String("chat-id", chatID))
			return false, nil
		}

		// Otherwise we verify the grant
		return o.canPostWithGrant(pk, chatID, grantBytes)
	}

	// Chat has no membership, check org permissions
	if o.config.OrganisationDescription.Members == nil {
		o.config.Logger.Debug("canPost, no members in org", zap.String("chat-id", chatID))
		return false, nil
	}

	// If member, they can post
	_, ok = o.config.OrganisationDescription.Members[common.PubkeyToHex(pk)]
	if ok {
		return true, nil
	}

	// Not a member and no grant, can't post
	if !ok && grantBytes == nil {
		o.config.Logger.Debug("canPost, not a member in org", zap.String("chat-id", chatID), zap.String("pubkey", common.PubkeyToHex(pk)))
		return false, nil
	}

	return o.canPostWithGrant(pk, chatID, grantBytes)
}

func (o *Organisation) canPostWithGrant(pk *ecdsa.PublicKey, chatID string, grantBytes []byte) (bool, error) {
	grant, err := o.VerifyGrantSignature(grantBytes)
	if err != nil {
		return false, err
	}
	// If the clock is lower or equal is invalid
	if grant.Clock <= o.config.OrganisationDescription.Clock {
		return false, nil
	}

	if grant.MemberId == nil {
		return false, nil
	}

	grantPk, err := crypto.DecompressPubkey(grant.MemberId)
	if err != nil {
		return false, nil
	}

	if !common.IsPubKeyEqual(grantPk, pk) {
		return false, nil
	}

	if chatID != grant.ChatId {
		return false, nil
	}

	return true, nil
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

func (o *Organisation) increaseClock() {
	o.config.OrganisationDescription.Clock = o.nextClock()
}

func (o *Organisation) nextClock() uint64 {
	return o.config.OrganisationDescription.Clock + 1
}
