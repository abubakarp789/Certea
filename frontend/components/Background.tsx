export default function Background() {
    return (
        <div className="fixed inset-0 -z-50 bg-background-landing h-full w-full overflow-hidden">
            {/* Gradient Globs */}
            <div className="absolute top-[-10%] left-[-10%] w-[500px] h-[500px] bg-primary/20 rounded-full blur-[120px] animate-pulse-slow" />
            <div className="absolute bottom-[-10%] right-[-10%] w-[500px] h-[500px] bg-accent/10 rounded-full blur-[120px] animate-pulse-slow delay-1000" />

            {/* Grid Pattern */}
            <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px]" />

            {/* Radial Overlay */}
            <div className="absolute inset-0 bg-background-landing/80 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(120,119,198,0.15),rgba(255,255,255,0))]" />
        </div>
    );
}
