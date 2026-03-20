import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import Hero from "@/components/sections/Hero";
import ThreatTicker from "@/components/sections/ThreatTicker";
import HowItWorks from "@/components/sections/HowItWorks";
import MainTool from "@/components/sections/MainTool";
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
      <Verification />
      <Comparison />
      <Footer />
    </main>
  );
}
