<template>
  <div class="min-h-screen bg-gradient-to-r from-neutral-900 via-emerald-900/40 to-neutral-900 p-4">
    <div class="max-w-4xl mx-auto pt-12">
      <!-- Hero Section -->
      <div class="rounded-2xl border border-white/10 bg-white/5 backdrop-blur-md p-8 mb-8 text-center">
        <h1 class="text-4xl font-bold text-gray-100 mb-4">SecScore</h1>
        <p class="text-gray-400 mb-8 max-w-2xl mx-auto">
          Time-aware CVE threat scoring using public signals
          <span class="text-emerald-400 text-sm">[Coming soon]</span>
        </p>

        <!-- CVE Input Form -->
        <form @submit.prevent="analyzeCve" class="max-w-md mx-auto">
          <div class="flex gap-3">
            <div class="flex-1">
              <input
                v-model="cveInput"
                type="text"
                placeholder="CVE-2024-12345"
                class="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
                :class="{ 'border-red-500': inputError }"
              />
            </div>
            <button
              type="submit"
              class="px-6 py-3 rounded-md bg-emerald-500/10 text-lg font-semibold text-emerald-500 ring-1 ring-inset ring-emerald-600/10 hover:opacity-80 transition ease-in-out duration-200"
            >

              Analyze
            </button>
          </div>
          <p v-if="inputError" class="text-red-400 text-sm mt-2 text-left">{{ inputError }}</p>
        </form>
      </div>

      <!-- Results Panel -->
      <div v-if="showResults" class="rounded-2xl border border-white/10 bg-white/5 backdrop-blur-md p-8">
        <div class="flex items-center justify-between mb-6">
          <h2 class="text-2xl font-semibold text-gray-100">Analysis Results</h2>
          <div class="flex items-center gap-2">
            <span class="text-sm text-gray-400">[Coming soon] Live data & API</span>
          </div>
        </div>

        <!-- Score Badge -->
        <div class="flex justify-center mb-8">
          <div class="text-center">
            <div class="inline-flex items-center justify-center w-24 h-24 rounded-full bg-gradient-to-br from-emerald-500 to-emerald-600 text-white text-3xl font-bold mb-2">
              {{ mockData.secscore }}
            </div>
            <p class="text-gray-400 text-sm">SecScore</p>
          </div>
        </div>

        <!-- Key Facts -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
          <div class="text-center">
            <p class="text-gray-400 text-xs uppercase tracking-wide mb-1">CVE ID</p>
            <p class="text-gray-100 font-medium">{{ mockData.cveId }}</p>
          </div>
          <div class="text-center">
            <p class="text-gray-400 text-xs uppercase tracking-wide mb-1">Published</p>
            <p class="text-gray-100 font-medium">{{ formatDate(mockData.publishedDate) }}</p>
          </div>
          <div class="text-center">
            <p class="text-gray-400 text-xs uppercase tracking-wide mb-1">CVSS Base</p>
            <p class="text-gray-100 font-medium">{{ mockData.cvssBase }}</p>
          </div>
          <div class="text-center">
            <p class="text-gray-400 text-xs uppercase tracking-wide mb-1">EPSS Score</p>
            <p class="text-gray-100 font-medium">{{ mockData.epss?.score.toFixed(2) }}</p>
          </div>
          <div class="text-center">
            <p class="text-gray-400 text-xs uppercase tracking-wide mb-1">KEV Listed</p>
            <p class="text-gray-100 font-medium">{{ mockData.kev ? 'Yes' : 'No' }}</p>
          </div>
          <div class="text-center">
            <p class="text-gray-400 text-xs uppercase tracking-wide mb-1">Exploit PoC</p>
            <p class="text-gray-100 font-medium">{{ mockData.exploits.length > 0 ? 'Yes' : 'No' }}</p>
          </div>
        </div>

        <!-- Signals -->
        <div class="mb-8">
          <h3 class="text-lg font-semibold text-gray-100 mb-4">Data Signals</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div class="p-4 rounded-lg border border-white/10 bg-white/5">
              <div class="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center mb-2">
                <svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
              </div>
              <p class="text-gray-100 font-medium text-sm">NVD</p>
              <p class="text-gray-400 text-xs">Active</p>
            </div>
            <div class="p-4 rounded-lg border border-white/10 bg-white/5">
              <div class="w-8 h-8 bg-emerald-500/20 rounded-lg flex items-center justify-center mb-2">
                <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                </svg>
              </div>
              <p class="text-gray-100 font-medium text-sm">EPSS</p>
              <p class="text-gray-400 text-xs">{{ (mockData.epss?.percentile * 100).toFixed(0) }}th %ile</p>
            </div>
            <div class="p-4 rounded-lg border border-white/10 bg-white/5">
              <div class="w-8 h-8 bg-red-500/20 rounded-lg flex items-center justify-center mb-2">
                <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z"></path>
                </svg>
              </div>
              <p class="text-gray-100 font-medium text-sm">KEV</p>
              <p class="text-gray-400 text-xs">{{ mockData.kev ? 'Listed' : 'Not listed' }}</p>
            </div>
            <div class="p-4 rounded-lg border border-white/10 bg-white/5">
              <div class="w-8 h-8 bg-orange-500/20 rounded-lg flex items-center justify-center mb-2">
                <svg class="w-4 h-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"></path>
                </svg>
              </div>
              <p class="text-gray-100 font-medium text-sm">ExploitDB</p>
              <p class="text-gray-400 text-xs">{{ mockData.exploits.length }} PoC{{ mockData.exploits.length !== 1 ? 's' : '' }}</p>
            </div>
            <div class="p-4 rounded-lg border border-white/10 bg-white/5 opacity-50">
              <div class="w-8 h-8 bg-gray-500/20 rounded-lg flex items-center justify-center mb-2">
                <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
              </div>
              <p class="text-gray-100 font-medium text-sm">OSV</p>
              <p class="text-gray-400 text-xs">Coming soon</p>
            </div>
          </div>
        </div>

        <!-- Timeline -->
        <div class="mb-8">
          <h3 class="text-lg font-semibold text-gray-100 mb-4">Timeline</h3>
          <div class="relative">
            <div class="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-600"></div>
            <div class="space-y-6">
              <div class="flex items-center">
                <div class="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center relative z-10">
                  <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                  </svg>
                </div>
                <div class="ml-4">
                  <p class="text-gray-100 font-medium">CVE Published</p>
                  <p class="text-gray-400 text-sm">{{ formatDate(mockData.publishedDate) }}</p>
                </div>
              </div>
              <div v-if="mockData.exploits.length > 0" class="flex items-center">
                <div class="w-8 h-8 bg-orange-500 rounded-full flex items-center justify-center relative z-10">
                  <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"></path>
                  </svg>
                </div>
                <div class="ml-4">
                  <p class="text-gray-100 font-medium">Exploit PoC Published</p>
                  <p class="text-gray-400 text-sm">{{ formatDate(mockData.exploits[0].publishedDate) }}</p>
                </div>
              </div>
              <div class="flex items-center">
                <div class="w-8 h-8 bg-emerald-500 rounded-full flex items-center justify-center relative z-10">
                  <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                </div>
                <div class="ml-4">
                  <p class="text-gray-100 font-medium">Analysis Computed</p>
                  <p class="text-gray-400 text-sm">{{ formatDate(mockData.computedAt) }}</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Explanation -->
        <div>
          <h3 class="text-lg font-semibold text-gray-100 mb-4">Scoring Explanation</h3>
          <div class="space-y-3">
            <div v-for="item in mockData.explanation" :key="item.title" class="p-4 rounded-lg border border-white/10 bg-white/5">
              <div class="flex items-start justify-between">
                <div>
                  <h4 class="text-gray-100 font-medium">{{ item.title }}</h4>
                  <p class="text-gray-400 text-sm mt-1">{{ item.detail }}</p>
                </div>
                <span class="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">{{ item.source }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { SecScoreResponse } from "~/types/types";

const cveInput = ref('')
const inputError = ref('')
const showResults = ref(false)

// Mock data
const mockData: SecScoreResponse = {
  cveId: "CVE-2024-12345",
  publishedDate: "2024-02-12T00:00:00Z",
  cvssBase: 7.5,
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  secscore: 7.9,
  exploitProb: 0.58,
  modelCategory: "php",
  modelParams: { mu: -0.4286, lambda: 14.56, kappa: 1.128 },
  epss: { score: 0.62, percentile: 0.62, fetchedAt: "2025-01-05T10:21:00Z" },
  exploits: [
    { source: "exploitdb", url: "https://www.exploit-db.com/exploits/00000", publishedDate: "2024-03-05T00:00:00Z" }
  ],
  kev: false,
  explanation: [
    { title: "Time-aware", detail: "AL-CDF exploit probability 0.58 (category: php)", source: "secscore" },
    { title: "EPSS", detail: "EPSS 0.62 (62nd percentile)", source: "epss" },
    { title: "Exploit PoC", detail: "ExploitDB entry since 2024-03-05", source: "exploitdb" }
  ],
  computedAt: "2025-01-05T10:21:00Z"
}

// CVE validation regex
const cveRegex = /^CVE-\d{4}-\d{4,}$/

// Methods
const analyzeCve = () => {
  inputError.value = ''

  if (!cveInput.value.trim()) {
    inputError.value = 'Please enter a CVE ID'
    return
  }

  if (!cveRegex.test(cveInput.value.trim())) {
    inputError.value = 'Invalid CVE format. Use format: CVE-YYYY-NNNN'
    return
  }

  // Update mock data with user input
  mockData.cveId = cveInput.value.trim()
  showResults.value = true
}

const formatDate = (dateString: string | null): string => {
  if (!dateString) return 'N/A'
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })
}

useSeoMeta({
  title: 'Time-aware CVE Threat Scoring',
  description: 'Open-source PoC to enrich CVEs with public signals (NVD, EPSS, CISA KEV, ExploitDB, OSV) and compute a time-aware SecScore for realistic prioritization. Paste a CVE ID and get instant context.',
  ogTitle: 'SecScore • Time-aware CVE Threat Scoring',
  ogDescription: 'Enrich CVEs with public data and compute a time-aware SecScore using an Asymmetric Laplace model plus EPSS, KEV, and ExploitDB signals.',
  ogImage: '/images/og/secscore.webp',
  ogType: 'website',
  ogUrl: 'https://secscore.nicokempe.de/',
  twitterTitle: 'SecScore • Time-aware CVE Threat Scoring',
  twitterDescription: 'Open-source Nuxt + Nitro PoC that turns a CVE ID into an explainable, time-aware SecScore using public threat signals.',
  twitterImage: '/images/og/secscore.webp',
  twitterCard: 'summary_large_image',
});
</script>
