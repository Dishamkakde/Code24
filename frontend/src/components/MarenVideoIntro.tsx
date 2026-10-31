import React, { useState, useRef, useEffect } from 'react';

export const MarenVideoIntro: React.FC = () => {
  const [isLeaving, setIsLeaving] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);

  useEffect(() => {
    // Lock body scrolling while intro is visible
    document.body.classList.add('overflow-hidden');
    if (videoRef.current) {
      videoRef.current.play().catch(() => {
        // Autoplay policy handled silently
      });
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
      aria-label="Welcome to MAREN"
    >
      {/* Background Video */}
      <div className="absolute inset-0 w-full h-full overflow-hidden pointer-events-none z-[1]">
        <video
          ref={videoRef}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 min-w-full min-h-full w-screen h-screen object-cover object-center"
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
        >
          <source
            src="https://d2ol7oe51mr4n9.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/0b9dbcc0-b9fc-4c2c-9418-458e4e829c59.mp4"
            type="video/mp4"
          />
        </video>
      </div>

      {/* Editorial Content Overlay */}
      <div className="relative z-[2] w-full h-full flex flex-col justify-between items-center py-12 px-6 pointer-events-none">
        <div className="h-6"></div>

        {/* Center MAREN Logo */}
        <div className="flex-1 flex items-center justify-center text-center">
          <h1 className="font-serif italic font-normal text-white uppercase tracking-[0.18em] text-5xl sm:text-7xl lg:text-8xl leading-none drop-shadow-2xl">
            MAREN
          </h1>
        </div>

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
