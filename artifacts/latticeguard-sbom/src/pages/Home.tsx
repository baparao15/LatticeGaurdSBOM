import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import Hero from "@/components/sections/Hero";
import ThreatTicker from "@/components/sections/ThreatTicker";
import HowItWorks from "@/components/sections/HowItWorks";
import MainTool from "@/components/sections/MainTool";
import QuantumThreat from "@/components/sections/QuantumThreat";
import AuditLog from "@/components/sections/AuditLog";
import CiCdPanel from "@/components/sections/CiCdPanel";
import Verification from "@/components/sections/Verification";
import Comparison from "@/components/sections/Comparison";

export default function Home() {
  return (
    <main className="min-h-screen relative flex flex-col">
      <Navbar />
      <Hero />
      <ThreatTicker />
      <HowItWorks />
      <MainTool />
      <QuantumThreat />
      <AuditLog />
      <CiCdPanel />
      <Verification />
      <Footer />
    </main>
  );
}
