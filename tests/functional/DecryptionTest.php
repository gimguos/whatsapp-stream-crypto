<?php

namespace Tests\Functional;

require_once __DIR__ . '/../../vendor/autoload.php';

use WhatsAppStream\Crypto\CryptoManager;
use WhatsAppStream\Enum\MediaType;
use WhatsAppStream\Stream\DecryptingStream;
use RuntimeException;

class DecryptionTest
{
    private const TEST_DATA_DIR = __DIR__ . '/../data';
    private CryptoManager $cryptoManager;

    public function __construct()
    {
        $this->cryptoManager = new CryptoManager();
    }

    public function testDecryption(string $mediaType): void
    {
        $encryptedFile = self::TEST_DATA_DIR . "/$mediaType.encrypted";
        $outputFile = self::TEST_DATA_DIR . "/$mediaType.decrypted";
        $keyFile = self::TEST_DATA_DIR . "/$mediaType.key";
        $originalFile = self::TEST_DATA_DIR . "/$mediaType.original";

        if (!file_exists($encryptedFile)) {
            throw new RuntimeException("Error: Input file '$encryptedFile' does not exist");
        }

        if (!file_exists($keyFile)) {
            throw new RuntimeException("Error: Key file '$keyFile' does not exist");
        }

        $mediaKey = file_get_contents($keyFile);
        echo "Media key length: " . strlen($mediaKey) . " bytes\n";
        echo "Media key hex: " . bin2hex($mediaKey) . "\n";
        
        $encryptedStream = new \GuzzleHttp\Psr7\Stream(fopen($encryptedFile, 'r'));

        $mediaTypeEnum = match($mediaType) {
            'IMAGE' => MediaType::IMAGE,
            'VIDEO' => MediaType::VIDEO,
            'AUDIO' => MediaType::AUDIO,
            default => MediaType::DOCUMENT
        };

        $decryptingStream = new DecryptingStream(
            $encryptedStream,
            $mediaKey,
            $mediaTypeEnum,
            $this->cryptoManager
        );

        $targetHandle = fopen($outputFile, 'wb');
        $totalBytes = 0;

        while (!$decryptingStream->eof()) {
            $chunk = $decryptingStream->read(65536);
            $bytesWritten = fwrite($targetHandle, $chunk);
            if ($bytesWritten === false) {
                throw new RuntimeException('Failed to write to output file');
            }
            $totalBytes += $bytesWritten;
        }

        fclose($targetHandle);
        $decryptingStream->close();

        // Проверяем результат
        if (!file_exists($originalFile)) {
            echo "Warning: Original file not found, skipping comparison\n";
            return;
        }

        $originalSize = filesize($originalFile);
        $decryptedSize = filesize($outputFile);

        echo "Original file size: $originalSize bytes\n";
        echo "Decrypted file size: $decryptedSize bytes\n";
        echo "Original file hash: " . hash_file('sha256', $originalFile) . "\n";
        echo "Decrypted file hash: " . hash_file('sha256', $outputFile) . "\n";

        if ($originalSize !== $decryptedSize) {
            throw new RuntimeException(
                "Size mismatch: original=$originalSize bytes, decrypted=$decryptedSize bytes"
            );
        }

        if (hash_file('sha256', $originalFile) !== hash_file('sha256', $outputFile)) {
            throw new RuntimeException("Content mismatch between original and decrypted files");
        }

        echo "Successfully decrypted $mediaType file ($totalBytes bytes)\n";
        echo "Verification passed: size and content match the original\n";
    }
}

// Запускаем тесты
$test = new DecryptionTest();

try {
    foreach (['AUDIO', 'IMAGE', 'VIDEO'] as $mediaType) {
        echo "\nTesting $mediaType decryption:\n";
        echo "------------------------\n";
        $test->testDecryption($mediaType);
    }
    echo "\nAll tests passed successfully!\n";
} catch (RuntimeException $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
} 