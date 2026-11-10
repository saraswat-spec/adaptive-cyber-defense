package com.cyberattack.soc.dto;

import com.cyberattack.soc.model.enums.FeedbackType;
import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotNull;

public class FeedbackRequestDTO {

    @NotNull(message = "feedback_type is required")
    @JsonAlias({"feedback_type", "feedbackType"})
    private FeedbackType feedbackType;

    @JsonAlias({"analyst_notes", "analystNotes"})
    private String analystNotes;

    @JsonAlias({"adjust_threshold", "adjustThreshold"})
    private Boolean adjustThreshold = true;

    public FeedbackRequestDTO() {}

    public FeedbackType getFeedbackType() { return feedbackType; }
    public void setFeedbackType(FeedbackType feedbackType) { this.feedbackType = feedbackType; }

    public String getAnalystNotes() { return analystNotes; }
    public void setAnalystNotes(String analystNotes) { this.analystNotes = analystNotes; }

    public Boolean getAdjustThreshold() { return adjustThreshold; }
    public void setAdjustThreshold(Boolean adjustThreshold) { this.adjustThreshold = adjustThreshold; }
}
