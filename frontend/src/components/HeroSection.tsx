import React from "react";
import { Play, FileCode2 } from "lucide-react";

interface HeroSectionProps {
  onScrollToTesting: () => void;
  activeDeviceCount: number;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  onScrollToTesting,
  activeDeviceCount,
}) => {
  return (
    <section className="hero-section">
      <div className="hero-badge">
        <span className="hero-badge-dot" />
        <span className="hero-badge-text">
          {activeDeviceCount > 0
            ? `${activeDeviceCount} IoT Honeypot Node Active`
            : "Embedded NIDS Telemetry Active"}
        </span>
      </div>

      <h1 className="hero-title">
        IoT Honeypot <span className="hero-title-accent">Intrusion Monitor</span>
      </h1>

      <p className="hero-description">
        Continuous network intrusion detection, real-time threat classification,
        and deterministic rule evaluation engineered for the NXP FRDM-RW612
        embedded platform.
      </p>

      <div className="hero-actions">
        <button
          type="button"
          className="hero-btn-primary"
          onClick={onScrollToTesting}
        >
          <Play size={15} />
          <span>Simulate Telemetry</span>
        </button>
        <a
          href="http://127.0.0.1:8000/docs"
          target="_blank"
          rel="noopener noreferrer"
          className="hero-btn-secondary"
        >
          <FileCode2 size={15} />
          <span>API Specification</span>
        </a>
      </div>
    </section>
  );
};
