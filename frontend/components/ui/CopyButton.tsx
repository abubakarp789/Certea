'use client';

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { copyToClipboard } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';

interface CopyButtonProps {
    text: string;
    label?: string;
    className?: string;
    showToastNotification?: boolean;
}

export function CopyButton({
    text,
    label = 'Copy',
    className = '',
    showToastNotification = true
}: CopyButtonProps) {
    const [copied, setCopied] = useState(false);
    const { showToast } = useToast();

    const handleCopy = async () => {
        const success = await copyToClipboard(text);
        if (success) {
            setCopied(true);
            if (showToastNotification) {
                showToast('Copied to clipboard!', 'success');
            }
            setTimeout(() => setCopied(false), 2000);
        }
    };

    return (
        <button
            onClick={handleCopy}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors font-medium text-sm ${copied
                    ? 'bg-success/10 text-success hover:bg-success/20'
                    : 'bg-accent/10 text-accent hover:bg-accent/20'
                } ${className}`}
        >
            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? 'Copied' : label}
        </button>
    );
}
