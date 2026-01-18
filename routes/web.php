<?php

// Routes are registered from EasyAuthServiceProvider::registerRoutes().
// This is done in an app->booted() callback so that override routes (e.g. /login)
// can be registered after Filament and reliably take precedence.
