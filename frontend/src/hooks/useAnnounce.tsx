/**
 * Screen Reader Announcement Hook
 *
 * Provides live region announcements for screen readers.
 * Implements ARIA live regions for dynamic content updates.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

export type AnnouncePolitenessSetting = 'polite' | 'assertive' | 'off';

export interface UseAnnounceOptions {
  /** Default politeness level */
  defaultPoliteness?: AnnouncePolitenessSetting;
  /** Delay before clearing announcement (ms) */
  clearDelay?: number;
  /** ID for the live region */
  regionId?: string;
}

export interface UseAnnounceReturn {
  /** Announce a message to screen readers */
  announce: (message: string, politeness?: AnnouncePolitenessSetting) => void;
  /** Clear the current announcement */
  clear: () => void;
  /** Component to render the live region */
  LiveRegion: React.FC;
}

// Singleton container for live regions
let liveRegionContainer: HTMLDivElement | null = null;

function getLiveRegionContainer(): HTMLDivElement {
  if (!liveRegionContainer && typeof document !== 'undefined') {
    liveRegionContainer = document.createElement('div');
    liveRegionContainer.id = 'aria-live-regions';
    liveRegionContainer.setAttribute('aria-hidden', 'false');
    liveRegionContainer.style.cssText = `
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    `;
    document.body.appendChild(liveRegionContainer);
  }
  return liveRegionContainer!;
}

export function useAnnounce({
  defaultPoliteness = 'polite',
  clearDelay = 1000,
  regionId = 'live-announcer',
}: UseAnnounceOptions = {}): UseAnnounceReturn {
  const [message, setMessage] = useState('');
  const [politeness, setPoliteness] = useState<AnnouncePolitenessSetting>(defaultPoliteness);
  const timeoutRef = useRef<NodeJS.Timeout>();

  const clear = useCallback(() => {
    setMessage('');
  }, []);

  const announce = useCallback(
    (newMessage: string, newPoliteness: AnnouncePolitenessSetting = defaultPoliteness) => {
      // Clear any pending timeout
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }

      // Clear message first to ensure re-announcement of same message
      setMessage('');

      // Use requestAnimationFrame to ensure the clear takes effect
      requestAnimationFrame(() => {
        setPoliteness(newPoliteness);
        setMessage(newMessage);

        // Auto-clear after delay
        if (clearDelay > 0) {
          timeoutRef.current = setTimeout(() => {
            clear();
          }, clearDelay);
        }
      });
    },
    [defaultPoliteness, clearDelay, clear]
  );

  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const LiveRegion: React.FC = useCallback(() => {
    const container = getLiveRegionContainer();

    return createPortal(
      <div
        id={regionId}
        role="status"
        aria-live={politeness}
        aria-atomic="true"
        style={{
          position: 'absolute',
          width: '1px',
          height: '1px',
          padding: 0,
          margin: '-1px',
          overflow: 'hidden',
          clip: 'rect(0, 0, 0, 0)',
          whiteSpace: 'nowrap',
          border: 0,
        }}
      >
        {message}
      </div>,
      container
    );
  }, [regionId, politeness, message]);

  return {
    announce,
    clear,
    LiveRegion,
  };
}

/**
 * Global announcer for use outside of React components
 */
class GlobalAnnouncer {
  private politeRegion: HTMLDivElement | null = null;
  private assertiveRegion: HTMLDivElement | null = null;

  constructor() {
    if (typeof document !== 'undefined') {
      this.init();
    }
  }

  private init() {
    const container = getLiveRegionContainer();

    this.politeRegion = document.createElement('div');
    this.politeRegion.id = 'global-announcer-polite';
    this.politeRegion.setAttribute('role', 'status');
    this.politeRegion.setAttribute('aria-live', 'polite');
    this.politeRegion.setAttribute('aria-atomic', 'true');
    container.appendChild(this.politeRegion);

    this.assertiveRegion = document.createElement('div');
    this.assertiveRegion.id = 'global-announcer-assertive';
    this.assertiveRegion.setAttribute('role', 'alert');
    this.assertiveRegion.setAttribute('aria-live', 'assertive');
    this.assertiveRegion.setAttribute('aria-atomic', 'true');
    container.appendChild(this.assertiveRegion);
  }

  announce(message: string, politeness: AnnouncePolitenessSetting = 'polite') {
    const region = politeness === 'assertive' ? this.assertiveRegion : this.politeRegion;
    if (!region) return;

    // Clear and re-set to trigger announcement
    region.textContent = '';
    requestAnimationFrame(() => {
      region.textContent = message;
    });
  }

  clear() {
    if (this.politeRegion) this.politeRegion.textContent = '';
    if (this.assertiveRegion) this.assertiveRegion.textContent = '';
  }
}

export const globalAnnouncer = new GlobalAnnouncer();

/**
 * Announce helper functions
 */
export const announcePolite = (message: string) => globalAnnouncer.announce(message, 'polite');
export const announceAssertive = (message: string) => globalAnnouncer.announce(message, 'assertive');

export default useAnnounce;
