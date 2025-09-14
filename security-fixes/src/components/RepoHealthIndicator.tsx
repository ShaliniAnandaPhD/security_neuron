import React from 'react';
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Shield, Bug, TestTube, Zap } from "lucide-react";

// Sanitization utilities
const sanitizeString = (str: string | undefined): string => {
  if (!str || typeof str !== 'string') return '';
  
  // Remove potentially dangerous characters and limit length
  return str
    .replace(/[<>'"&]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/data:/gi, '')
    .substring(0, 100)
    .trim();
};

const sanitizeNumber = (num: any): number => {
  const parsed = Number(num);
  return isNaN(parsed) || !isFinite(parsed) ? 0 : Math.max(0, Math.min(100, parsed));
};

interface RepoHealthIndicatorProps {
  healthScore: number;
  codeRabbitIssues: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  securityVulnerabilities: number;
  testCoverage: number;
  autoFixEnabled: boolean;
  className?: string;
}

export const RepoHealthIndicator: React.FC<RepoHealthIndicatorProps> = ({
  healthScore,
  codeRabbitIssues,
  securityVulnerabilities,
  testCoverage,
  autoFixEnabled,
  className = ""
}) => {
  // Sanitize all inputs
  const safeHealthScore = sanitizeNumber(healthScore);
  const safeTestCoverage = sanitizeNumber(testCoverage);
  const safeSecurityVulns = sanitizeNumber(securityVulnerabilities);
  
  const safeCritical = sanitizeNumber(codeRabbitIssues?.critical);
  const safeHigh = sanitizeNumber(codeRabbitIssues?.high);
  const safeMedium = sanitizeNumber(codeRabbitIssues?.medium);
  const safeLow = sanitizeNumber(codeRabbitIssues?.low);

  const getHealthColor = (score: number): string => {
    if (score >= 80) return "text-green-600";
    if (score >= 60) return "text-yellow-600";
    return "text-red-600";
  };

  const getHealthBadgeVariant = (score: number) => {
    if (score >= 80) return "default";
    if (score >= 60) return "secondary";
    return "destructive";
  };