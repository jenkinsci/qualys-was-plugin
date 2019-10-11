package com.qualys.plugins.wasPlugin.QualysAuth;

class InvalidUserException extends Exception {
    @Override
    public String toString() {
        return "Invalid User";
    }
}
