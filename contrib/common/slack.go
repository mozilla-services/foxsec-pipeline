package common

import (
	"encoding/json"

	"cloud.google.com/go/pubsub"
)

type ActionType string

const (
	SlashCommand  ActionType = "slash_command"
	Interaction   ActionType = "interaction"
	ScheduledTask ActionType = "scheduled_task"
)

type SlashCommandData struct {
	Cmd         string
	ResponseURL string
	Text        string
	UserID      string
}

type InteractionData struct {
	ActionName  string
	CallbackID  string
	ResponseURL string
}

type TriggerData struct {
	Action       ActionType       `json:"action_type"`
	SlashCommand SlashCommandData `json:"slash_command,omitempty"`
	Interaction  InteractionData  `json:"interaction,omitempty"`
}

func PubSubMessageToTriggerData(psmsg pubsub.Message) (*TriggerData, error) {
	var td TriggerData
	err := json.Unmarshal(psmsg.Data, &td)
	if err != nil {
		return nil, err
	}
	return &td, nil
}

func (td *TriggerData) ToPubSubMessage() (*pubsub.Message, error) {
	buf, err := json.Marshal(td)
	if err != nil {
		return nil, err
	}
	return &pubsub.Message{Data: buf}, nil
}
