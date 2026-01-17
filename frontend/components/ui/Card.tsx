import React from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
  onClick?: () => void;
}

export default function Card({ children, className, hover = false, onClick }: CardProps) {
  const CardComponent = motion.div;

  const cardClasses = cn(
    'glass rounded-2xl p-8 transition-all',
    hover && 'cursor-pointer hover:-translate-y-2 hover:scale-102 hover:border-accent/30 hover:shadow-lg hover:shadow-accent/10',
    className
  );

  if (onClick) {
    return (
      <CardComponent
        whileHover={hover ? { y: -8, scale: 1.02 } : {}}
        onClick={onClick}
        className={cardClasses}
      >
        {children}
      </CardComponent>
    );
  }

  return <div className={cardClasses}>{children}</div>;
}
