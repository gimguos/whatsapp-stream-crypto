<?php

namespace Tests\Functional;

require_once __DIR__ . '/../../vendor/autoload.php';

use WhatsAppStream\Crypto\CryptoManager;
use WhatsAppStream\Enum\MediaType;
use RuntimeException;

class SidecarTest
{
    private const TEST_DATA_DIR = __DIR__ . '/../data';
    private CryptoManager $cryptoManager;

    public function __construct()
    {
        $this->cryptoManager = new CryptoManager();
    }

    public function testSidecarGeneration(string $mediaType): void
    {
        $encryptedFile = self::TEST_DATA_DIR . "/$mediaType.encrypted";
        $keyFile = self::TEST_DATA_DIR . "/$mediaType.key";
        $sidecarFile = self::TEST_DATA_DIR . "/$mediaType.test.sidecar";
        $originalSidecarFile = self::TEST_DATA_DIR . "/$mediaType.sidecar";

        if (!file_exists($encryptedFile)) {
            throw new RuntimeException("Error: Input file '$encryptedFile' does not exist");
        }

        if (!file_exists($keyFile)) {
            throw new RuntimeException("Error: Key file '$keyFile' does not exist");
        }

        $mediaKey = file_get_contents($keyFile);
        $encryptedData = file_get_contents($encryptedFile);

        $mediaTypeEnum = match($mediaType) {
            'IMAGE' => MediaType::IMAGE,
            'VIDEO' => MediaType::VIDEO,
            'AUDIO' => MediaType::AUDIO,
            default => MediaType::DOCUMENT
        };

        // Получаем расширенный ключ
        $expandedKey = $this->cryptoManager->expandMediaKey($mediaKey, $mediaTypeEnum);

        // Генерируем sidecar
        $sidecar = $this->cryptoManager->generateStreamingSidecar($encryptedData, $expandedKey['macKey']);
        file_put_contents($sidecarFile, $sidecar);

        echo "Generated sidecar file for $mediaType ($sidecarFile)\n";
        echo "Size: " . strlen($sidecar) . " bytes\n";

        // Проверяем с оригинальным sidecar файлом, если он есть
        if (file_exists($originalSidecarFile)) {
            $originalSidecar = file_get_contents($originalSidecarFile);
            if ($originalSidecar !== $sidecar) {
                throw new RuntimeException("Generated sidecar does not match the original");
            }
            echo "Verification passed: generated sidecar matches the original\n";
        }
    }
}

// Запускаем тесты
$test = new SidecarTest();

try {
    foreach (['AUDIO', 'IMAGE', 'VIDEO'] as $mediaType) {
        echo "\nTesting $mediaType sidecar generation:\n";
        echo "------------------------\n";
        $test->testSidecarGeneration($mediaType);
    }
    echo "\nAll tests passed successfully!\n";
} catch (RuntimeException $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
} 