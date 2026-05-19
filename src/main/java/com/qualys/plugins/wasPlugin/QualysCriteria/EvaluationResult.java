package com.qualys.plugins.wasPlugin.QualysCriteria;

@SuppressWarnings("URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD")
public class EvaluationResult {
    public String configured;
    public String found;
    public EvaluationResultValues result;

    public EvaluationResult() {
        this.configured = "";
        this.found = "";
        this.result = EvaluationResultValues.Pass;
    }

    public String getConfigured() {
        return configured;
    }

    public String getFound() {
        return found;
    }

    public EvaluationResultValues getResult() {
        return result;
    }
}