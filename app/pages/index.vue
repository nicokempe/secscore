<template>
  <div class="px-4 pb-16 pt-20 sm:px-6 lg:px-8">
    <div class="mx-auto max-w-4xl">
      <!-- Hero Section -->
      <div class="glass-card p-8 mb-8 text-center">
        <h1 class="text-4xl font-bold text-neutral-100 mb-4">
          Security Score
        </h1>
        <p class="text-neutral-400 mb-8 max-w-2xl mx-auto">
          Time-aware CVE threat scoring using public signals
        </p>

        <!-- CVE Input Form -->
        <form
          class="max-w-md mx-auto"
          @submit.prevent="analyzeCve"
        >
          <div class="flex gap-3">
            <div class="flex-1">
              <input
                v-model="cveInput"
                type="text"
                placeholder="CVE-2024-12345"
                :disabled="isLoading"
                class="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-lg text-neutral-100 placeholder-neutral-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed"
                :class="{ 'border-red-500': inputError }"
              >
            </div>
            <button
              type="submit"
              :disabled="isLoading || (isTurnstileEnabled && !turnstileToken)"
              class="inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-500/60 bg-cyan-500/10 px-6 py-3 text-base font-medium text-cyan-200 transition duration-200 hover:opacity-80 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed h-full"
            >
              <span v-if="!isLoading">Analyze</span>
              <div
                v-else
                class="flex items-center gap-2"
              >
                <div class="w-4 h-4 border-2 border-cyan-300/30 border-t-cyan-200 rounded-full animate-spin" />
                <span>Analyzing...</span>
              </div>
            </button>
          </div>
          <div
            v-if="isTurnstileEnabled"
            class="mt-4"
          >
            <NuxtTurnstile
              ref="turnstileRef"
              v-model="turnstileToken"
            />
          </div>
          <p
            v-if="inputError"
            class="text-red-400 text-sm mt-2 text-left"
          >
            {{ inputError }}
          </p>
          <p
            v-if="apiError"
            class="text-red-400 text-sm mt-2 text-left"
          >
            {{ apiError }}
          </p>
        </form>
      </div>

      <!-- Fancy Loading State -->
      <div
        v-if="isLoading && !showResults"
        class="glass-card p-8 mb-8"
      >
        <div class="text-center">
          <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-cyan-500/20 mb-4">
            <div class="w-8 h-8 border-3 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
          </div>
          <h3 class="text-lg font-semibold text-neutral-100 mb-2">
            Analyzing CVE
          </h3>
          <p class="text-neutral-400 text-sm mb-6">
            {{ loadingMessage }}
          </p>

          <!-- Loading Progress Indicators -->
          <div class="space-y-3 max-w-md mx-auto">
            <div
              v-for="(step, index) in loadingStepsSequence"
              :key="step.name"
              class="flex items-center gap-3 p-3 rounded-lg bg-white/5 border border-white/10"
              :class="{ 'opacity-50': index > currentLoadingStep }"
            >
              <div
                class="w-6 h-6 rounded-full flex items-center justify-center"
                :class="index < currentLoadingStep ? 'bg-cyan-500' : index === currentLoadingStep ? 'bg-cyan-500/50' : 'bg-neutral-600'"
              >
                <CheckIcon
                  v-if="index < currentLoadingStep"
                  class="w-3 h-3 text-white"
                />
                <div
                  v-else-if="index === currentLoadingStep"
                  class="w-2 h-2 bg-white rounded-full animate-pulse"
                />
                <div
                  v-else
                  class="w-2 h-2 bg-neutral-400 rounded-full"
                />
              </div>
              <span class="text-sm text-neutral-300">{{ step.label }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Not Found State -->
      <div
        v-if="notFound && !isLoading"
        class="glass-card p-8 mb-8 border border-red-500/30 bg-red-500/5"
      >
        <div class="flex items-start gap-4">
          <div class="w-12 h-12 rounded-full bg-red-500/15 flex items-center justify-center">
            <MagnifyingGlassCircleIcon class="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h3 class="text-lg font-semibold text-neutral-100 mb-1">
              We couldn't find that CVE
            </h3>
            <p class="text-neutral-300 text-sm mb-3">
              Double-check the identifier or try a different CVE ID. Some older or private CVEs may not be published in public sources yet.
            </p>
            <ul class="list-disc list-inside text-neutral-400 text-sm space-y-1">
              <li>Ensure the format is <span class="text-neutral-200">CVE-YYYY-NNNN</span></li>
              <li>Try the closest related vendor advisory or product bulletin</li>
              <li>Come back later as data sources update periodically</li>
            </ul>
          </div>
        </div>
      </div>

      <!-- Results Panel -->
      <div
        v-if="showResults && currentData"
        class="glass-card p-8"
      >
        <div class="flex items-center justify-between mb-6">
          <h2 class="text-2xl font-semibold text-neutral-100">
            Analysis Results
          </h2>
        </div>

        <!-- Score Badge -->
        <div class="flex justify-center mb-8">
          <div class="text-center relative group">
            <div class="inline-flex items-center justify-center w-24 h-24 rounded-full bg-gradient-to-br from-cyan-500 to-cyan-600 text-white text-3xl font-bold mb-2 cursor-help transition-transform hover:opacity-90">
              {{ currentData.secscore }}
            </div>
            <p class="text-neutral-400 text-sm">
              SecScore
            </p>

            <!-- Tooltip -->
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-2">
                SecScore Explained
              </h4>
              <p class="text-neutral-300 text-sm mb-2">
                A time-aware threat score combining multiple security signals:
              </p>
              <ul class="text-neutral-300 text-xs space-y-1">
                <li>• CVSS base score ({{ currentData.cvssBase }})</li>
                <li>• EPSS exploit probability ({{ (currentData.epss?.score || 0).toFixed(2) }})</li>
                <li>• Time-decay modeling</li>
                <li>• Public exploit availability</li>
              </ul>
            </div>
          </div>
        </div>

        <!-- Key Facts -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8 gap-4 mb-8">
          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              CVE ID
            </p>
            <p class="text-neutral-100 font-medium">
              {{ currentData.cveId }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                CVE Identifier
              </h4>
              <p class="text-neutral-300 text-sm">
                Common Vulnerabilities and Exposures - a unique identifier for publicly known security vulnerabilities.
              </p>
            </div>
          </div>

          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              Published
            </p>
            <p class="text-neutral-100 font-medium">
              {{ formatDateOrFallback(currentData.publishedDate) }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                Publication Date
              </h4>
              <p class="text-neutral-300 text-sm">
                When this vulnerability was first publicly disclosed in the National Vulnerability Database (NVD).
              </p>
            </div>
          </div>

          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              CVSS Base
            </p>
            <p class="text-neutral-100 font-medium">
              {{ currentData.cvssBase }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                CVSS Base Score
              </h4>
              <p class="text-neutral-300 text-sm">
                Common Vulnerability Scoring System - measures severity from 0-10. Higher scores indicate more severe vulnerabilities.
              </p>
            </div>
          </div>

          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              CVSS Version
            </p>
            <p class="text-neutral-100 font-medium">
              {{ resolveCvssVersionLabel(currentData.cvssVector, currentData.cvssVersion) }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                CVSS Version
              </h4>
              <p class="text-neutral-300 text-sm">
                Identifies whether the vulnerability was scored with CVSS v3.x or v4.0.
              </p>
              <p class="text-neutral-500 text-xs break-words">
                Vector: {{ currentData.cvssVector || 'Not published by NVD.' }}
              </p>
            </div>
          </div>

          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              EPSS Score
            </p>
            <p class="text-neutral-100 font-medium">
              {{ (currentData.epss?.score || 0).toFixed(2) }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                EPSS Score
              </h4>
              <p class="text-neutral-300 text-sm">
                Exploit Prediction Scoring System - probability (0-1) that this vulnerability will be exploited in the wild within 30 days.
              </p>
            </div>
          </div>

          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              Exploit Probability
            </p>
            <p class="text-neutral-100 font-medium">
              {{ formatExploitProbability(currentData.exploitProb) }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                Time-Adjusted Exploit Odds
              </h4>
              <p class="text-neutral-300 text-sm">
                Probability of exploitation estimated by the temporal model based on CVE age and historical behavior for the {{ currentData.modelCategory }} category.
              </p>
            </div>
          </div>

          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              KEV Listed
            </p>
            <p class="text-neutral-100 font-medium">
              {{ currentData.kev ? 'Yes' : 'No' }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                KEV Status
              </h4>
              <p class="text-neutral-300 text-sm">
                Known Exploited Vulnerabilities - CISA's catalog of vulnerabilities actively exploited by threat actors.
              </p>
            </div>
          </div>

          <div class="text-center relative group cursor-help">
            <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
              Exploit PoC
            </p>
            <p class="text-neutral-100 font-medium">
              {{ currentData.exploits.length > 0 ? 'Yes' : 'No' }}
            </p>
            <div class="tooltip">
              <h4 class="font-semibold text-white mb-1">
                Proof of Concept
              </h4>
              <p class="text-neutral-300 text-sm">
                Whether public exploit code or demonstrations are available, making the vulnerability easier to exploit.
              </p>
            </div>
          </div>
        </div>

        <!-- Packages Affected (OSV) -->
        <div
          v-if="(currentData.osv?.length ?? 0) > 0"
          class="mb-8"
        >
          <h3 class="text-lg font-semibold text-neutral-100 mb-4">
            Packages Affected
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div
              v-for="(pkg, index) in currentData.osv"
              :key="`${pkg.ecosystem ?? 'unknown'}-${pkg.package ?? index}`"
              class="p-4 rounded-lg border border-white/10 bg-white/5"
            >
              <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
                {{ pkg.ecosystem || 'Unknown ecosystem' }}
              </p>
              <p class="text-neutral-100 font-medium mb-2">
                {{ pkg.package || 'Unknown package' }}
              </p>
              <ul class="space-y-1">
                <li
                  v-for="(range, rangeIdx) in pkg.ranges"
                  :key="rangeIdx"
                  class="text-neutral-300 text-sm"
                >
                  {{ formatOsvRange(range) }}
                </li>
                <li
                  v-if="!pkg.ranges || pkg.ranges.length === 0"
                  class="text-neutral-500 text-sm"
                >
                  Version details unavailable
                </li>
              </ul>
            </div>
          </div>
        </div>

        <!-- Signals -->
        <div class="mb-8">
          <h3 class="text-lg font-semibold text-neutral-100 mb-4">
            Data Signals
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div class="signal-card relative group cursor-help">
              <div class="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center mb-2">
                <ShieldCheckIcon class="w-4 h-4 text-blue-400" />
              </div>
              <p class="text-neutral-100 font-medium text-sm">
                NVD
              </p>
              <p class="text-neutral-400 text-xs">
                Active
              </p>
              <div class="tooltip">
                <h4 class="font-semibold text-white mb-1">
                  National Vulnerability Database
                </h4>
                <p class="text-neutral-300 text-sm">
                  US government repository of standards-based vulnerability management data. Provides official CVE details and CVSS scores.
                </p>
              </div>
            </div>

            <div class="signal-card relative group cursor-help">
              <div class="w-8 h-8 bg-cyan-500/20 rounded-lg flex items-center justify-center mb-2">
                <BoltIcon class="w-4 h-4 text-cyan-400" />
              </div>
              <p class="text-neutral-100 font-medium text-sm">
                EPSS
              </p>
              <p class="text-neutral-400 text-xs">
                {{ ((currentData.epss?.percentile || 0) * 100).toFixed(0) }}th %ile
              </p>
              <div class="tooltip">
                <h4 class="font-semibold text-white mb-1">
                  Exploit Prediction Scoring System
                </h4>
                <p class="text-neutral-300 text-sm">
                  Machine learning model that predicts the likelihood of exploitation. This vulnerability ranks in the {{ ((currentData.epss?.percentile || 0) * 100).toFixed(0) }}th percentile.
                </p>
              </div>
            </div>

            <div class="signal-card relative group cursor-help">
              <div class="w-8 h-8 bg-red-500/20 rounded-lg flex items-center justify-center mb-2">
                <ExclamationTriangleIcon class="w-4 h-4 text-red-400" />
              </div>
              <p class="text-neutral-100 font-medium text-sm">
                KEV
              </p>
              <p class="text-neutral-400 text-xs">
                {{ currentData.kev ? 'Listed' : 'Not listed' }}
              </p>
              <div class="tooltip">
                <h4 class="font-semibold text-white mb-1">
                  Known Exploited Vulnerabilities
                </h4>
                <p class="text-neutral-300 text-sm">
                  CISA's authoritative list of vulnerabilities known to be actively exploited by malicious actors. {{ currentData.kev ? 'This CVE is actively being exploited.' : 'No active exploitation detected yet.' }}
                </p>
              </div>
            </div>

            <div class="signal-card relative group cursor-help">
              <div class="w-8 h-8 bg-orange-500/20 rounded-lg flex items-center justify-center mb-2">
                <FireIcon class="w-4 h-4 text-orange-400" />
              </div>
              <p class="text-neutral-100 font-medium text-sm">
                ExploitDB
              </p>
              <p class="text-neutral-400 text-xs">
                {{ currentData.exploits.length }} PoC{{ currentData.exploits.length !== 1 ? 's' : '' }}
              </p>
              <div class="tooltip">
                <h4 class="font-semibold text-white mb-1">
                  Exploit Database
                </h4>
                <p class="text-neutral-300 text-sm">
                  Archive of public exploits and proof-of-concepts. {{ currentData.exploits.length > 0 ? `Found ${currentData.exploits.length} public exploit(s).` : 'No public exploits found yet.' }}
                </p>
              </div>
            </div>

            <div class="signal-card relative group cursor-help">
              <div class="w-8 h-8 bg-neutral-500/20 rounded-lg flex items-center justify-center mb-2">
                <ClockIcon class="w-4 h-4 text-neutral-400" />
              </div>
              <p class="text-neutral-100 font-medium text-sm">
                OSV
              </p>
              <p class="text-neutral-400 text-xs">
                {{ osvPackagesCount > 0 ? `${osvPackagesCount} package${osvPackagesCount === 1 ? '' : 's'}` : 'No advisories' }}
              </p>
              <div class="tooltip">
                <h4 class="font-semibold text-white mb-1">
                  Open Source Vulnerabilities
                </h4>
                <p class="text-neutral-300 text-sm">
                  Google's database of vulnerabilities affecting open source projects. {{ osvPackagesCount > 0 ? `OSV lists ${osvPackagesCount} affected package${osvPackagesCount === 1 ? '' : 's'} for this CVE.` : 'No OSV packages are currently linked to this CVE.' }}
                </p>
              </div>
            </div>
          </div>
        </div>

        <!-- Model Insights -->
        <div class="mb-8">
          <h3 class="text-lg font-semibold text-neutral-100 mb-4">
            Model Insights
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            <div class="insight-card">
              <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
                Category
              </p>
              <p class="text-neutral-100 font-medium">
                {{ formatModelCategory(currentData.modelCategory) }}
              </p>
              <p class="text-neutral-400 text-sm mt-2">
                Determines which asymmetric Laplace distribution is used to model exploit timing.
              </p>
            </div>
            <div class="insight-card">
              <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
                Model Parameters (μ, λ, κ)
              </p>
              <p class="text-neutral-100 font-medium">
                {{ formatModelParams(currentData.modelParams) }}
              </p>
              <p class="text-neutral-400 text-sm mt-2">
                Captures the shape of the exploit probability curve for this category.
              </p>
            </div>
            <div class="insight-card">
              <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
                CVSS Vector
              </p>
              <p class="text-neutral-100 font-medium break-words">
                {{ currentData.cvssVector || 'Vector unavailable' }}
              </p>
              <p class="text-neutral-400 text-sm mt-2">
                Indicates attack prerequisites such as access, complexity, and required privileges.
              </p>
            </div>
            <div class="insight-card">
              <p class="text-neutral-400 text-xs uppercase tracking-wide mb-1">
                Computed At
              </p>
              <p class="text-neutral-100 font-medium">
                {{ formatDateOrFallback(currentData.computedAt) }}
              </p>
              <p class="text-neutral-400 text-sm mt-2">
                Timestamp of when the SecScore service generated this analysis snapshot.
              </p>
            </div>
          </div>
        </div>

        <!-- Timeline -->
        <div class="mb-8">
          <h3 class="text-lg font-semibold text-neutral-100 mb-4">
            Timeline
          </h3>
          <div class="relative">
            <div class="absolute left-4 top-0 bottom-0 w-0.5 bg-neutral-600" />
            <div class="space-y-6">
              <div class="flex items-center">
                <div class="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center relative z-10">
                  <PlusIcon class="w-4 h-4 text-white" />
                </div>
                <div class="ml-4">
                  <p class="text-neutral-100 font-medium">
                    CVE Published
                  </p>
                  <p class="text-neutral-400 text-sm">
                    {{ formatDateOrFallback(currentData.publishedDate) }}
                  </p>
                </div>
              </div>
              <div
                v-if="currentData.exploits.length > 0"
                class="flex items-center"
              >
                <div class="w-8 h-8 bg-orange-500 rounded-full flex items-center justify-center relative z-10">
                  <FireIcon class="w-4 h-4 text-white" />
                </div>
                <div class="ml-4">
                  <p class="text-neutral-100 font-medium">
                    Exploit PoC Published
                  </p>
                  <p class="text-neutral-400 text-sm">
                    {{ formatDateOrFallback(currentData.exploits[0]?.publishedDate ?? null) }}
                  </p>
                </div>
              </div>
              <div class="flex items-center">
                <div class="w-8 h-8 bg-cyan-500 rounded-full flex items-center justify-center relative z-10">
                  <ClockIcon class="w-4 h-4 text-white" />
                </div>
                <div class="ml-4">
                  <p class="text-neutral-100 font-medium">
                    Analysis Computed
                  </p>
                  <p class="text-neutral-400 text-sm">
                    {{ formatDateOrFallback(currentData.computedAt) }}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Explanation -->
        <div>
          <h3 class="text-lg font-semibold text-neutral-100 mb-4">
            Scoring Explanation
          </h3>
          <div class="space-y-3">
            <div
              v-for="item in currentData.explanation"
              :key="item.title"
              class="explanation-card"
            >
              <div class="flex items-start justify-between">
                <div>
                  <h4 class="text-neutral-100 font-medium">
                    {{ item.title }}
                  </h4>
                  <p class="text-neutral-400 text-sm mt-1">
                    {{ item.detail }}
                  </p>
                </div>
                <span class="text-xs text-neutral-500 bg-neutral-800 px-2 py-1 rounded">{{ item.source }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { BoltIcon, CheckIcon, ClockIcon, ExclamationTriangleIcon, FireIcon, MagnifyingGlassCircleIcon, PlusIcon, ShieldCheckIcon } from '@heroicons/vue/20/solid';
import type { OsvRangeEvent, OsvVersionRange, SecScoreResponse } from '~/types/secscore.types';

const cveInput = ref('');
const inputError = ref('');
const apiError = ref('');
const showResults = ref(false);
const isLoading = ref(false);
const currentLoadingStep = ref(0);
const defaultLoadingMessage = 'Preparing analysis...';
const loadingMessage = ref(defaultLoadingMessage);
const notFound = ref(false);

const runtimeConfig = useRuntimeConfig();
const isTurnstileEnabled = computed(() => Boolean(runtimeConfig.public?.turnstile?.enabled));
const turnstileToken = ref('');
type TurnstileComponentInstance = { reset: () => void };
const turnstileRef = ref<TurnstileComponentInstance | null>(null);

const LOADING_STEP_INTERVAL_MS = 500;
const LOADING_COMPLETION_INTERVAL_MS = 120;
let loadingStepInterval: ReturnType<typeof setInterval> | undefined;
let loadingCompletionInterval: ReturnType<typeof setInterval> | undefined;

const loadingStepsSequence = [
  { name: 'validate', label: 'Validating CVE format' },
  { name: 'fetch_nvd', label: 'Fetching NVD data' },
  { name: 'fetch_epss', label: 'Getting EPSS scores' },
  { name: 'check_kev', label: 'Checking KEV status' },
  { name: 'scan_exploits', label: 'Scanning for exploits' },
  { name: 'compute', label: 'Computing SecScore' },
];

const secscoreData = ref<SecScoreResponse | null>(null);

const currentData = computed(() => secscoreData.value);

const osvPackagesCount = computed(() => currentData.value?.osv?.length ?? 0);

const cveIdentifierPattern = /^CVE-\d{4}-\d{4,}$/;

const stopLoadingProgressTimers = () => {
  if (loadingStepInterval) {
    clearInterval(loadingStepInterval);
    loadingStepInterval = undefined;
  }

  if (loadingCompletionInterval) {
    clearInterval(loadingCompletionInterval);
    loadingCompletionInterval = undefined;
  }
};

const startLoadingProgressTimers = () => {
  stopLoadingProgressTimers();

  if (loadingStepsSequence.length === 0) {
    loadingMessage.value = defaultLoadingMessage;
    return;
  }

  currentLoadingStep.value = 0;
  loadingMessage.value = loadingStepsSequence[0]?.label ?? defaultLoadingMessage;

  if (loadingStepsSequence.length === 1) {
    return;
  }

  loadingStepInterval = setInterval(() => {
    if (currentLoadingStep.value >= loadingStepsSequence.length - 1) {
      if (loadingStepInterval) {
        clearInterval(loadingStepInterval);
        loadingStepInterval = undefined;
      }
      return;
    }

    currentLoadingStep.value += 1;
    loadingMessage.value = loadingStepsSequence[currentLoadingStep.value]?.label ?? defaultLoadingMessage;
  }, LOADING_STEP_INTERVAL_MS);
};

const completeLoadingProgressSequence = async (finalMessage: string) =>
  new Promise<void>((resolve) => {
    stopLoadingProgressTimers();

    if (loadingStepsSequence.length === 0) {
      loadingMessage.value = finalMessage;
      resolve();
      return;
    }

    const finalizeLoadingCompletion = () => {
      stopLoadingProgressTimers();
      currentLoadingStep.value = loadingStepsSequence.length;
      loadingMessage.value = finalMessage;
      resolve();
    };

    if (currentLoadingStep.value >= loadingStepsSequence.length - 1) {
      finalizeLoadingCompletion();
      return;
    }

    loadingCompletionInterval = setInterval(() => {
      if (currentLoadingStep.value < loadingStepsSequence.length - 1) {
        currentLoadingStep.value += 1;
        loadingMessage.value = loadingStepsSequence[currentLoadingStep.value]?.label ?? defaultLoadingMessage;
        return;
      }

      finalizeLoadingCompletion();
    }, LOADING_COMPLETION_INTERVAL_MS);
  });

const analyzeCve = async () => {
  inputError.value = '';
  apiError.value = '';

  if (!cveInput.value.trim()) {
    inputError.value = 'Please enter a CVE ID';
    return;
  }

  const normalizedCveIdentifier = cveInput.value.trim().toUpperCase();

  if (!cveIdentifierPattern.test(normalizedCveIdentifier)) {
    inputError.value = 'Invalid CVE format. Use format: CVE-YYYY-NNNN';
    return;
  }

  if (isTurnstileEnabled.value && !turnstileToken.value) {
    apiError.value = 'Please complete the verification challenge.';
    return;
  }

  cveInput.value = normalizedCveIdentifier;

  // Start loading sequence
  secscoreData.value = null;
  isLoading.value = true;
  showResults.value = false;
  notFound.value = false;
  startLoadingProgressTimers();

  let finalCompletionMessage = 'SecScore ready';
  let shouldShowResults = false;

  try {
    const headers: Record<string, string> = {};
    if (isTurnstileEnabled.value && turnstileToken.value) {
      headers['cf-turnstile-response'] = turnstileToken.value;
    }

    const enrichmentResponse = await $fetch<SecScoreResponse>(`/api/v1/enrich/cve/${encodeURIComponent(normalizedCveIdentifier)}`, {
      headers,
    });
    secscoreData.value = enrichmentResponse;
    shouldShowResults = true;
    notFound.value = false;
  }
  catch (error: unknown) {
    const errorStatusCode = extractStatusCodeFromError(error);

    if (errorStatusCode === 404) {
      notFound.value = true;
      apiError.value = '';
      finalCompletionMessage = 'CVE not found';
    }
    else {
      apiError.value = resolveErrorMessageFromUnknown(error);
      finalCompletionMessage = 'Failed to analyze CVE';
    }
  }
  finally {
    await completeLoadingProgressSequence(finalCompletionMessage);
    isLoading.value = false;
    showResults.value = shouldShowResults;
    if (isTurnstileEnabled.value) {
      turnstileRef.value?.reset();
      turnstileToken.value = '';
    }
  }
};

const formatDateOrFallback = (dateString: string | null): string => {
  if (!dateString) return 'N/A';
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

const isNonNullRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null;

const extractStatusCodeFromError = (error: unknown): number | null => {
  if (!isNonNullRecord(error)) {
    return null;
  }

  if (typeof (error as { statusCode?: unknown }).statusCode === 'number') {
    return (error as { statusCode: number }).statusCode;
  }

  if (typeof (error as { status?: unknown }).status === 'number') {
    return (error as { status: number }).status;
  }

  if ('response' in error) {
    const response = (error as { response?: unknown }).response;
    if (isNonNullRecord(response) && typeof response.status === 'number') {
      return response.status;
    }
  }

  return null;
};

const resolveErrorMessageFromUnknown = (error: unknown): string => {
  if (typeof error === 'string') {
    return error;
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  if (isNonNullRecord(error)) {
    if ('data' in error) {
      const data = (error as { data?: unknown }).data;
      if (isNonNullRecord(data) && typeof data.message === 'string') {
        return data.message;
      }
    }

    if ('statusMessage' in error && typeof (error as { statusMessage?: unknown }).statusMessage === 'string') {
      return (error as { statusMessage: string }).statusMessage;
    }

    if ('message' in error && typeof (error as { message?: unknown }).message === 'string') {
      return (error as { message: string }).message;
    }
  }

  return 'Failed to analyze the CVE. Please try again later.';
};

const MAX_OSV_RANGE_LENGTH = 72;

const truncateText = (value: string, maxLength = MAX_OSV_RANGE_LENGTH): string => {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 1))}…`;
};

const formatOsvEvent = (event: OsvRangeEvent): string | null => {
  const eventSegments: string[] = [];

  if (event.introduced) {
    eventSegments.push(`>= ${event.introduced}`);
  }

  if (event.fixed) {
    eventSegments.push(`< ${event.fixed}`);
  }

  if (event.lastAffected) {
    eventSegments.push(`<= ${event.lastAffected}`);
  }

  if (event.limit) {
    eventSegments.push(event.limit);
  }

  if (eventSegments.length === 0) {
    return null;
  }

  return eventSegments.join(' / ');
};

const formatOsvRange = (range: OsvVersionRange): string => {
  const rangeSegments: string[] = [];

  if (range.type) {
    rangeSegments.push(range.type);
  }

  const formattedEventDescriptions = (range.events ?? [])
    .map((event) => {
      return formatOsvEvent(event);
    })
    .filter((value): value is string => {
      return Boolean(value);
    });

  if (formattedEventDescriptions.length > 0) {
    rangeSegments.push(formattedEventDescriptions.join('; '));
  }

  const rangeSummary = rangeSegments.join(' • ') || 'Version range unavailable';

  return truncateText(rangeSummary);
};

const inferCvssVersion = (vector: string): string | null => {
  const match = vector.match(/^CVSS:([0-9.]+)/i);
  return match?.[1] ?? null;
};

const resolveCvssVersionLabel = (vector: string | null, version: string | null): string => {
  if (!vector) {
    return 'N/A';
  }

  const derivedVersion = version ?? inferCvssVersion(vector);
  if (!derivedVersion) {
    return 'Unknown';
  }

  return `v${derivedVersion}`;
};

const formatExploitProbability = (value: number): string => {
  if (!Number.isFinite(value)) {
    return 'N/A';
  }

  return `${(value * 100).toFixed(1)}%`;
};

const formatModelCategory = (value: string): string => {
  if (!value) {
    return 'Default';
  }

  return value.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
};

const formatModelParams = (params: SecScoreResponse['modelParams']): string => {
  const { mu, lambda, kappa } = params;
  const formattedMu = Number.isFinite(mu) ? mu.toFixed(2) : '–';
  const formattedLambda = Number.isFinite(lambda) ? lambda.toFixed(2) : '–';
  const formattedKappa = Number.isFinite(kappa) ? kappa.toFixed(2) : '–';
  return `${formattedMu}, ${formattedLambda}, ${formattedKappa}`;
};

onBeforeUnmount(() => {
  stopLoadingProgressTimers();
});

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

useHead({
  htmlAttrs: {
    lang: 'en',
  },
  link: [
    // Light mode SVG
    {
      rel: 'icon',
      type: 'image/svg+xml',
      href: '/favicon-light.svg',
      media: '(prefers-color-scheme: light)',
    },
    // Dark mode SVG
    {
      rel: 'icon',
      type: 'image/svg+xml',
      href: '/favicon-dark.svg',
      media: '(prefers-color-scheme: dark)',
    },
    // Legacy ICO fallback
    {
      rel: 'icon',
      type: 'image/x-icon',
      href: '/favicon.ico',
    },
  ],
  meta: [
    {
      name: 'application-name',
      content: 'SecScore',
    },
    {
      name: 'theme-color',
      content: '#0f172a',
    },
    {
      name: 'author',
      content: 'Nico Kempe',
    },
    {
      name: 'robots',
      content: 'index, follow',
    },
  ],
});
</script>

<style scoped>
.glass-card {
  background: rgba(255, 255, 255, 0.05);
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 16px;
}

.signal-card {
  @apply p-4 rounded-lg border border-white/10 bg-white/5 transition-all duration-200 hover:bg-white/10 hover:border-white/20;
}

.explanation-card {
  @apply p-4 rounded-lg border border-white/10 bg-white/5;
}

.insight-card {
  @apply p-4 rounded-lg border border-white/10 bg-white/5 h-full;
}

/* Added tooltip styles for hover explanations */
.tooltip {
  @apply absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-neutral-900 border border-neutral-700 rounded-lg shadow-xl z-50 w-64 opacity-0 pointer-events-none transition-all duration-200;
}

.group:hover .tooltip {
  @apply opacity-100 pointer-events-auto;
}

.tooltip::after {
  content: '';
  @apply absolute top-full left-1/2 transform -translate-x-1/2 border-4 border-transparent border-t-neutral-900;
}

/* Enhanced loading animations */
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

.animate-spin {
  animation: spin 1s linear infinite;
}

.border-3 {
  border-width: 3px;
}
</style>
