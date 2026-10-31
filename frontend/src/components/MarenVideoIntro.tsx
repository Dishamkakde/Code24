import React, { useState, useRef, useEffect } from 'react';
import { Volume2, VolumeX } from 'lucide-react';

export const MarenVideoIntro: React.FC = () => {
  const [isLeaving, setIsLeaving] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);

  useEffect(() => {
    // Lock body scrolling while intro is visible
    document.body.classList.add('overflow-hidden');

    if (videoRef.current) {
      videoRef.current.muted = false;
      const playPromise = videoRef.current.play();
      if (playPromise !== undefined) {
        playPromise
          .then(() => {
            setIsMuted(false);
          })
          .catch(() => {
            // Autoplay with sound restricted by browser; play muted and unmute on first gesture
            if (videoRef.current) {
              videoRef.current.muted = true;
              setIsMuted(true);
              videoRef.current.play().catch(() => {});
            }

            const unmuteOnInteraction = () => {
              if (videoRef.current) {
                videoRef.current.muted = false;
                setIsMuted(false);
              }
              window.removeEventListener('pointerdown', unmuteOnInteraction);
              window.removeEventListener('keydown', unmuteOnInteraction);
            };

            window.addEventListener('pointerdown', unmuteOnInteraction, { once: true });
            window.addEventListener('keydown', unmuteOnInteraction, { once: true });
          });
      }
    }

    return () => {
      document.body.classList.remove('overflow-hidden');
    };
  }, []);

  const handleDismiss = () => {
    if (isLeaving || isDismissed) return;
    setIsLeaving(true);
    document.body.classList.remove('overflow-hidden');

    setTimeout(() => {
      setIsDismissed(true);
      if (videoRef.current) {
        try {
          videoRef.current.pause();
        } catch (_) {}
      }
    }, 800);
  };

  const toggleSound = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (videoRef.current) {
      videoRef.current.muted = !videoRef.current.muted;
      setIsMuted(videoRef.current.muted);
      if (!videoRef.current.muted && videoRef.current.paused) {
        videoRef.current.play().catch(() => {});
      }
    }
  };

  if (isDismissed) return null;

  return (
    <aside
      id="marenVideoIntro"
      onClick={handleDismiss}
      className={`fixed inset-0 w-screen h-screen z-[999999] bg-black flex flex-col justify-between items-center overflow-hidden cursor-pointer select-none transition-all duration-[800ms] ease-[cubic-bezier(0.4,0,0.2,1)] ${
        isLeaving ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
      role="dialog"
      aria-modal="true"
      aria-label="Welcome"
    >
      {/* Background Video with Voice */}
      <div className="absolute inset-0 w-full h-full overflow-hidden pointer-events-none z-[1]">
        <video
          ref={videoRef}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 min-w-full min-h-full w-screen h-screen object-cover object-center"
          autoPlay
          loop
          playsInline
          preload="auto"
        >
          <source
            src="https://www.image2url.com/r2/default/videos/1793430693365-87bf0334-8aec-4a3b-b1da-56ee64bbd774.mp4"
            type="video/mp4"
          />
        </video>
      </div>

      {/* Editorial Content Overlay */}
      <div className="relative z-[2] w-full h-full flex flex-col justify-between items-center py-12 px-6 pointer-events-none">
        {/* Top Sound Control */}
        <div className="w-full flex justify-end">
          <button
            onClick={toggleSound}
            className="pointer-events-auto bg-black/45 backdrop-blur-md border border-white/30 text-white rounded-full px-4 py-2 inline-flex items-center gap-2 text-xs font-semibold tracking-widest uppercase transition-all duration-200 hover:bg-black/70 hover:border-white/60 hover:scale-105"
            aria-label="Toggle voice and sound"
          >
            {isMuted ? (
              <>
                <VolumeX className="w-4 h-4" />
                <span>UNMUTE VOICE</span>
              </>
            ) : (
              <>
                <Volume2 className="w-4 h-4" />
                <span>VOICE ON</span>
              </>
            )}
          </button>
        </div>

        {/* Center area without MAREN text */}
        <div className="flex-1 flex items-center justify-center text-center"></div>

        {/* Bottom ENTER Button */}
        <button
          id="marenIntroEnterBtn"
          onClick={(e) => {
            e.stopPropagation();
            handleDismiss();
          }}
          className="pointer-events-auto bg-transparent border-0 text-white cursor-pointer inline-flex flex-col items-center gap-1.5 py-3 px-6 transition-transform duration-200 hover:translate-y-0.5 hover:opacity-85 focus:outline-none focus:ring-2 focus:ring-white/50 rounded-lg"
          aria-label="Enter website"
        >
          <span className="text-[11px] font-semibold tracking-[0.35em] uppercase text-white drop-shadow-md">
            ENTER
          </span>
          <svg
            className="w-4 h-4 text-white animate-bounce drop-shadow-md"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            viewBox="0 0 24 24"
          >
            <line x1="12" y1="5" x2="12" y2="19"></line>
            <polyline points="19 12 12 19 5 12"></polyline>
          </svg>
        </button>
      </div>
    </aside>
  );
};
