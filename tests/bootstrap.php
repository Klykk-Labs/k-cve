<?php
// De rena klasserna testas utan WordPress. ABSPATH sätts bara för att passera filernas guard.
define( 'ABSPATH', __DIR__ . '/' );
require __DIR__ . '/../src/autoload.php';

function kcve_fixture( string $name ): array {
	return json_decode( file_get_contents( __DIR__ . '/fixtures/' . $name ), true );
}
