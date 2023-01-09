package label_api

import "time"

type GetLabelsRequest struct {
	SourceIDs []string
	Entities  []string
	Labels    []string
	Limit     int
}

type Label struct {
	Label      string  `json:"label"`
	Confidence float32 `json:"confidence"`
	Entity     string  `json:"entity"`
	EntityType string  `json:"entityType"`
	Remove     bool    `json:"remove"`
}

type LabelEvent struct {
	Id        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Label     *Label    `json:"label"`
	Source    struct {
		Bot struct {
			Image     string `json:"image"`
			ImageHash string `json:"imageHash"`
			Id        string `json:"id"`
			Manifest  string `json:"manifest"`
		} `json:"bot"`
		AlertHash string `json:"alertHash"`
		AlertId   string `json:"alertId"`
		Id        string `json:"id"`
	} `json:"source"`
}

type LabelResponse struct {
	PageToken *int          `json:"pageToken"`
	Events    []*LabelEvent `json:"events"`
}
