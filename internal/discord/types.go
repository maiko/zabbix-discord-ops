package discord

type Interaction struct {
	ID            string          `json:"id"`
	ApplicationID string          `json:"application_id"`
	Type          int             `json:"type"`
	Token         string          `json:"token"`
	GuildID       string          `json:"guild_id"`
	ChannelID     string          `json:"channel_id"`
	Data          InteractionData `json:"data"`
	Member        Member          `json:"member"`
	Message       Message         `json:"message"`
}

type InteractionData struct {
	Name       string              `json:"name"`
	CustomID   string              `json:"custom_id"`
	Options    []InteractionOption `json:"options"`
	Components []ActionRow         `json:"components"`
}

type InteractionOption struct {
	Name    string              `json:"name"`
	Type    int                 `json:"type"`
	Value   any                 `json:"value"`
	Focused bool                `json:"focused"`
	Options []InteractionOption `json:"options"`
}

type Member struct {
	User  User     `json:"user"`
	Roles []string `json:"roles"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type ActionRow struct {
	Type       int         `json:"type"`
	Components []Component `json:"components"`
}

type Component struct {
	Type     int    `json:"type"`
	CustomID string `json:"custom_id"`
	Value    string `json:"value"`
}
