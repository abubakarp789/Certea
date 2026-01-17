'use client';

import { motion } from 'framer-motion';
import { ArrowRight, ShieldCheck, FileKey, ChevronRight } from 'lucide-react';
import Link from 'next/link';

export default function Hero() {
    return (
        <section className="relative pt-20 pb-32 overflow-hidden">
            <div className="container px-4 mx-auto relative z-10">
                <div className="flex flex-col lg:flex-row items-center gap-12 lg:gap-20">

                    {/* Text Content */}
                    <div className="flex-1 text-center lg:text-left">
                        <motion.div
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            transition={{ duration: 0.5 }}
                            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-accent/10 border border-accent/20 text-accent text-sm font-medium mb-6"
                        >
                            <ShieldCheck className="w-4 h-4" />
                            <span>Enterprise-Grade Security</span>
                        </motion.div>

                        <motion.h1
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.5, delay: 0.1 }}
                            className="text-5xl lg:text-7xl font-bold font-display tracking-tight text-white mb-6 leading-[1.1]"
                        >
                            Trust Every <br />
                            <span className="text-transparent bg-clip-text bg-gradient-to-r from-accent to-blue-500">
                                Digital Byte
                            </span>
                        </motion.h1>

                        <motion.p
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.5, delay: 0.2 }}
                            className="text-lg text-text-secondary max-w-2xl mx-auto lg:mx-0 mb-8 leading-relaxed"
                        >
                            Certea provides the world's most advanced cryptographic toolset for document integrity.
                            Sign, verify, and manage keys with RSA-4096 encryption.
                        </motion.p>

                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.5, delay: 0.3 }}
                            className="flex flex-col sm:flex-row items-center gap-4 justify-center lg:justify-start"
                        >
                            <Link href="/sign-file" className="w-full sm:w-auto">
                                <button className="w-full sm:w-auto px-8 py-4 bg-accent hover:bg-accent-hover text-background-secondary font-bold rounded-xl transition-all shadow-[0_0_20px_-5px_rgba(0,242,255,0.4)] hover:shadow-[0_0_30px_-5px_rgba(0,242,255,0.6)] flex items-center justify-center gap-2 group">
                                    Start Signing
                                    <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                                </button>
                            </Link>

                            <Link href="/generate" className="w-full sm:w-auto">
                                <button className="w-full sm:w-auto px-8 py-4 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-semibold rounded-xl transition-all flex items-center justify-center gap-2 backdrop-blur-sm">
                                    <FileKey className="w-5 h-5 text-accent" />
                                    Generate Keys
                                </button>
                            </Link>
                        </motion.div>
                    </div>

                    {/* Visual/Graphic Element */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ duration: 0.7 }}
                        className="flex-1 relative"
                    >
                        <div className="relative w-full aspect-square max-w-[500px] mx-auto">
                            {/* Abstract Glowing Shield/Lock Representation */}
                            <div className="absolute inset-0 bg-gradient-to-tr from-accent/20 to-blue-500/20 rounded-full blur-[100px]" />

                            <div className="relative z-10 w-full h-full bg-glass-bg border border-glass-border rounded-3xl p-8 backdrop-blur-xl shadow-2xl flex flex-col justify-between overflow-hidden group">
                                {/* Decorative header */}
                                <div className="flex items-center justify-between mb-8 opacity-50">
                                    <div className="flex gap-2">
                                        <div className="w-3 h-3 rounded-full bg-red-500" />
                                        <div className="w-3 h-3 rounded-full bg-yellow-500" />
                                        <div className="w-3 h-3 rounded-full bg-green-500" />
                                    </div>
                                    <div className="text-xs font-mono">SECURE_SHELL_V2.0</div>
                                </div>

                                {/* Main Graphic Content - Dashboard Preview style */}
                                <div className="space-y-4">
                                    <div className="h-2 w-1/3 bg-white/10 rounded-full" />
                                    <div className="h-32 w-full bg-gradient-to-br from-white/5 to-transparent rounded-xl border border-white/5 p-4 flex items-center justify-center relative overflow-hidden">
                                        <div className="absolute inset-0 bg-accent/5 animate-pulse-slow" />
                                        <ShieldCheck className="w-16 h-16 text-accent drop-shadow-[0_0_15px_rgba(0,242,255,0.5)]" />
                                    </div>
                                    <div className="flex gap-4">
                                        <div className="h-20 w-1/2 bg-white/5 rounded-xl border border-white/5" />
                                        <div className="h-20 w-1/2 bg-white/5 rounded-xl border border-white/5" />
                                    </div>
                                </div>

                                <div className="mt-8 pt-4 border-t border-white/10 flex justify-between items-center text-sm text-text-muted font-mono">
                                    <span>STATUS: PROTECTED</span>
                                    <span className="text-success animate-pulse">● ONLINE</span>
                                </div>
                            </div>

                            {/* Floating Badges */}
                            <motion.div
                                animate={{ y: [-10, 10, -10] }}
                                transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                                className="absolute -right-8 top-20 bg-background-secondary border border-border p-4 rounded-xl shadow-xl flex items-center gap-3"
                            >
                                <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center text-green-500">
                                    <ShieldCheck size={20} />
                                </div>
                                <div>
                                    <div className="text-xs text-text-muted">Verification</div>
                                    <div className="font-bold text-white">Success</div>
                                </div>
                            </motion.div>

                            <motion.div
                                animate={{ y: [10, -10, 10] }}
                                transition={{ duration: 5, repeat: Infinity, ease: "easeInOut", delay: 1 }}
                                className="absolute -left-8 bottom-20 bg-background-secondary border border-border p-4 rounded-xl shadow-xl flex items-center gap-3"
                            >
                                <div className="w-10 h-10 rounded-lg bg-accent/20 flex items-center justify-center text-accent">
                                    <FileKey size={20} />
                                </div>
                                <div>
                                    <div className="text-xs text-text-muted">Encryption</div>
                                    <div className="font-bold text-white">RSA-4096</div>
                                </div>
                            </motion.div>
                        </div>
                    </motion.div>
                </div>
            </div>
        </section>
    );
}
