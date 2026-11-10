package com.cyberattack.soc.dto;

import com.cyberattack.soc.model.enums.ActionType;
import jakarta.validation.constraints.NotNull;

public class MitigationRequestDTO {

    @NotNull(message = "action_type is required")
    private ActionType actionType = ActionType.BLOCK_IP;

    private String executionMode = "SIMULATED";

    public MitigationRequestDTO() {}

    public ActionType getActionType() { return actionType; }
    public void setActionType(ActionType actionType) { this.actionType = actionType; }

    public String getExecutionMode() { return executionMode; }
    public void setExecutionMode(String executionMode) { this.executionMode = executionMode; }
}
