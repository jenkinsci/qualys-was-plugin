package com.qualys.plugins.wasPlugin.QualysClient;

import com.google.gson.JsonObject;

public class QualysCSResponse extends QualysAPIResponse{
    public JsonObject response;

    public QualysCSResponse() {
        super();
        response = null;
    }
}
