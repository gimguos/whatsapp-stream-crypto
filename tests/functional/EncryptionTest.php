<?php

namespace Tests\Functional;

require_once __DIR__ . '/../../vendor/autoload.php';

use WhatsAppStream\Crypto\CryptoManager;
use WhatsAppStream\Enum\MediaType;
use WhatsAppStream\Stream\EncryptingStream;
use RuntimeException;

class EncryptionTest
{
    private const TEST_DATA_DIR = __DIR__ . '/../data';
    private CryptoManager $cryptoManager;

    public function __construct()
    {
        $this->cryptoManager = new CryptoManager();
    }

    public function testEncryption(string $mediaType): void
    {
        $originalFile = self::TEST_DATA_DIR . "/$mediaType.original";
        $outputFile = self::TEST_DATA_DIR . "/$mediaType.test.encrypted";
        $keyFile = self::TEST_DATA_DIR . "/$mediaType.key";

        if (!file_exists($originalFile)) {
            throw new RuntimeException("Error: Input file '$originalFile' does not exist");
        }

        // Генерируем новый ключ для теста
        $mediaKey = random_bytes(32);
        file_put_contents($keyFile . '.test', $mediaKey);

        $inputStream = new \GuzzleHttp\Psr7\Stream(fopen($originalFile, 'r'));

        $mediaTypeEnum = match($mediaType) {
            'IMAGE' => MediaType::IMAGE,
            'VIDEO' => MediaType::VIDEO,
            'AUDIO' => MediaType::AUDIO,
            default => MediaType::DOCUMENT
        };

        $encryptingStream = new EncryptingStream(
            $inputStream,
            $mediaKey,
            $mediaTypeEnum,
            $this->cryptoManager
        );

        $targetHandle = fopen($outputFile, 'wb');
        $totalBytes = 0;

        while (!$encryptingStream->eof()) {
            $chunk = $encryptingStream->read(65536);
            $bytesWritten = fwrite($targetHandle, $chunk);
            if ($bytesWritten === false) {
                throw new RuntimeException('Failed to write to output file');
            }
            $totalBytes += $bytesWritten;
        }

        fclose($targetHandle);
        $encryptingStream->close();

        echo "Successfully encrypted $mediaType file ($totalBytes bytes)\n";
        echo "Test key saved to: $keyFile.test\n";

        // Проверяем, что зашифрованный файл можно расшифровать
        $decryptTest = new DecryptionTest();
        try {
            $decryptTest->testDecryption($mediaType . '.test');
            echo "Verification passed: file successfully encrypted and decrypted back\n";
        } catch (RuntimeException $e) {
            throw new RuntimeException("Verification failed: " . $e->getMessage());
        }
    }
}

// Запускаем тесты
$test = new EncryptionTest();

try {
    foreach (['AUDIO', 'IMAGE', 'VIDEO'] as $mediaType) {
        echo "\nTesting $mediaType encryption:\n";
        echo "------------------------\n";
        $test->testEncryption($mediaType);
    }
    echo "\nAll tests passed successfully!\n";
} catch (RuntimeException $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
} 