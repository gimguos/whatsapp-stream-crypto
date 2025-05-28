<?php

namespace WhatsAppStream\Enum;

/**
 * Перечисление типов медиафайлов с их соответствующими информационными строками для HKDF
 * Эти строки используются как контекстная информация при расширении ключа
 */
enum MediaType: string
{
    /**
     * Тип для изображений, использует строку 'WhatsApp Image Keys' как контекст HKDF
     */
    case IMAGE = 'WhatsApp Image Keys';

    /**
     * Тип для видео, использует строку 'WhatsApp Video Keys' как контекст HKDF
     */
    case VIDEO = 'WhatsApp Video Keys';

    /**
     * Тип для аудио, использует строку 'WhatsApp Audio Keys' как контекст HKDF
     */
    case AUDIO = 'WhatsApp Audio Keys';

    /**
     * Тип для документов, использует строку 'WhatsApp Document Keys' как контекст HKDF
     */
    case DOCUMENT = 'WhatsApp Document Keys';
} 