<?php
/**
 * Bygger build/k-cve.zip: det som installeras på kundsiter och laddas upp som release-asset.
 * Innehåller bara k-cve.php, uninstall.php, src/ och vendor/ utan dev-beroenden — inga tester,
 * README eller CLAUDE.md (de skulle annars vara läsbara via webben på kundens server).
 *
 * Användning: php bin/build.php [förväntad-version]
 * Med en version (t.ex. från git-taggen v0.2.0) avbryts bygget om pluginets version inte stämmer.
 */

$root  = dirname( __DIR__ );
$build = $root . '/build';
$stage = $build . '/k-cve';

$main = file_get_contents( $root . '/k-cve.php' );
preg_match( '/^ \* Version:\s*(\S+)/m', $main, $header );
preg_match( "/define\( 'KCVE_VERSION', '([^']+)' \)/", $main, $constant );
$version = $header[1] ?? '';
if ( '' === $version || ( $constant[1] ?? '' ) !== $version ) {
	fail( "Versionen i headern ($version) och KCVE_VERSION (" . ( $constant[1] ?? '?' ) . ') måste vara samma.' );
}
$expected = isset( $argv[1] ) ? ltrim( $argv[1], 'v' ) : null;
if ( null !== $expected && $expected !== $version ) {
	fail( "Taggen säger $expected men k-cve.php säger $version." );
}

remove( $build );
mkdir( $stage, 0777, true );
foreach ( [ 'k-cve.php', 'uninstall.php', 'composer.json', 'composer.lock' ] as $file ) {
	copy( $root . '/' . $file, $stage . '/' . $file );
}
copy_dir( $root . '/src', $stage . '/src' );

// Installera produktionsberoenden i byggkatalogen, så att den lokala vendor/ (med phpunit) lämnas orörd.
passthru( 'composer install --no-dev --optimize-autoloader --no-interaction --quiet --working-dir=' . escapeshellarg( $stage ), $code );
if ( 0 !== $code ) {
	fail( 'composer install misslyckades.' );
}
unlink( $stage . '/composer.json' );
unlink( $stage . '/composer.lock' );

$zip_path = $build . '/k-cve.zip';
$zip      = new ZipArchive();
$zip->open( $zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE );
$files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $stage, FilesystemIterator::SKIP_DOTS ) );
foreach ( $files as $file ) {
	// Mappen i zippen måste heta k-cve: WordPress använder den som slug, och uppdateringarna matchar på den.
	$zip->addFile( $file->getPathname(), 'k-cve/' . str_replace( '\\', '/', substr( $file->getPathname(), strlen( $stage ) + 1 ) ) );
}
$count = $zip->numFiles;
$zip->close();

echo "Byggde build/k-cve.zip (version $version, $count filer, " . round( filesize( $zip_path ) / 1024 ) . " kB)\n";

function copy_dir( string $from, string $to ): void {
	mkdir( $to, 0777, true );
	foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $from, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST ) as $item ) {
		$target = $to . '/' . substr( $item->getPathname(), strlen( $from ) + 1 );
		$item->isDir() ? mkdir( $target, 0777, true ) : copy( $item->getPathname(), $target );
	}
}

function remove( string $path ): void {
	if ( ! file_exists( $path ) ) {
		return;
	}
	foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST ) as $item ) {
		$item->isDir() ? rmdir( $item->getPathname() ) : unlink( $item->getPathname() );
	}
	rmdir( $path );
}

function fail( string $message ): void {
	fwrite( STDERR, "Bygget avbröts: $message\n" );
	exit( 1 );
}
