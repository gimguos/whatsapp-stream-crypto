<?php

namespace WhatsAppStream\Tests;

use GuzzleHttp\Psr7\Stream;
use PHPUnit\Framework\TestCase;
use WhatsAppStream\Enum\MediaType;
use WhatsAppStream\StreamFactory;

class StreamTest extends TestCase
{
    private StreamFactory $factory;
    private string $testData;
    private string $mediaKey;

    protected function setUp(): void
    {
        $this->factory = new StreamFactory();
        $this->testData = 'Hello, WhatsApp!';
        $this->mediaKey = random_bytes(32);
    }

    public function testEncryptionAndDecryption(): void
    {
        $stream = $this->createStream($this->testData);
        
        // Encrypt
        $encryptedStream = $this->factory->createEncryptingStream(
            $stream,
            $this->mediaKey,
            MediaType::IMAGE
        );
        
        $encryptedData = $encryptedStream->getContents();
        $this->assertNotEquals($this->testData, $encryptedData);
        
        // Decrypt
        $decryptStream = $this->factory->createDecryptingStream(
            $this->createStream($encryptedData),
            $this->mediaKey,
            MediaType::IMAGE
        );
        
        $decryptedData = $decryptStream->getContents();
        $this->assertEquals($this->testData, $decryptedData);
    }

    public function testStreamingSidecar(): void
    {
        $sidecar = $this->factory->generateStreamingSidecar(
            $this->testData,
            $this->mediaKey,
            MediaType::VIDEO
        );
        
        $this->assertNotEmpty($sidecar);
    }

    private function createStream(string $content): Stream
    {
        $handle = fopen('php://temp', 'r+');
        fwrite($handle, $content);
        rewind($handle);
        return new Stream($handle);
    }
} 