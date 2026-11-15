import type { LookupResult } from './indicators';
import {
  formatNetworkSegment,
  normalizeCountryCode,
  type HeatmapThresholdFilter,
} from './heatmapAnalytics';
import { computeAllIocConfidenceScores, type ConfidenceRiskLevel } from './riskScoring';

export interface GeoFeatureCollection {
  type: 'FeatureCollection';
  features: Array<{
    type: 'Feature';
    id: string;
    properties: { name: string };
    geometry: {
      type: 'Polygon';
      coordinates: number[][][];
    };
  }>;
}

/**
 * Lightweight, 100%-offline continental landmass GeoJSON for D3 geoNaturalEarth1().
 * Rings are stored CCW below and reversed into clockwise spherical winding for d3-geo.
 */
const RAW_WORLD_LAND_GEOJSON: GeoFeatureCollection = {
  type: 'FeatureCollection',
  features: [
    {
      type: 'Feature',
      id: 'north-america',
      properties: { name: 'North America' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-168, 65],
            [-162, 55],
            [-148, 60],
            [-136, 58],
            [-125, 49],
            [-124, 40],
            [-117, 32],
            [-110, 24],
            [-105, 20],
            [-95, 16],
            [-84, 10],
            [-78, 9],
            [-82, 15],
            [-87, 21],
            [-90, 21],
            [-97, 26],
            [-94, 29],
            [-83, 29],
            [-81, 25],
            [-80, 31],
            [-75, 36],
            [-70, 42],
            [-66, 45],
            [-60, 47],
            [-55, 52],
            [-64, 60],
            [-78, 62],
            [-85, 68],
            [-95, 71],
            [-115, 70],
            [-135, 69],
            [-156, 71],
            [-168, 65],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'greenland',
      properties: { name: 'Greenland' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-54, 68],
            [-45, 60],
            [-32, 68],
            [-20, 76],
            [-28, 82],
            [-48, 82],
            [-62, 77],
            [-54, 68],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'south-america',
      properties: { name: 'South America' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-80, 9],
            [-81, -4],
            [-76, -14],
            [-71, -18],
            [-73, -36],
            [-74, -46],
            [-69, -54],
            [-65, -52],
            [-62, -41],
            [-54, -34],
            [-48, -26],
            [-40, -21],
            [-35, -8],
            [-38, -4],
            [-50, 1],
            [-60, 8],
            [-70, 12],
            [-80, 9],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'uk-ireland',
      properties: { name: 'British Isles' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-10, 52],
            [-6, 50],
            [1.5, 51],
            [1.2, 53],
            [-2, 58],
            [-6, 58],
            [-10, 54],
            [-10, 52],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'europe',
      properties: { name: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-9, 37],
            [-1, 36],
            [4, 43],
            [9, 44],
            [12, 40],
            [16, 38],
            [23, 37],
            [26, 41],
            [29, 43],
            [35, 45],
            [39, 47],
            [42, 55],
            [42, 66],
            [31, 69],
            [25, 71],
            [15, 69],
            [5, 61],
            [9, 57],
            [12, 55],
            [19, 55],
            [14, 54],
            [8, 54],
            [4, 52],
            [-4, 48],
            [-2, 44],
            [-9, 43],
            [-9, 37],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'africa',
      properties: { name: 'Africa' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-17, 15],
            [-16, 8],
            [-8, 5],
            [3, 6],
            [9, 4],
            [12, -6],
            [14, -18],
            [18, -34],
            [27, -33],
            [33, -26],
            [40, -15],
            [41, -2],
            [51, 11],
            [43, 12],
            [38, 20],
            [33, 31],
            [22, 32],
            [11, 37],
            [2, 36],
            [-6, 35],
            [-13, 27],
            [-17, 15],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'madagascar',
      properties: { name: 'Madagascar' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [44, -25],
            [47, -25],
            [50, -15],
            [49, -12],
            [44, -17],
            [44, -25],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'asia',
      properties: { name: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [27, 41],
            [27, 36],
            [36, 36],
            [35, 29],
            [43, 13],
            [52, 16],
            [59, 22],
            [56, 26],
            [50, 29],
            [57, 25],
            [67, 24],
            [72, 19],
            [77, 8],
            [82, 16],
            [89, 22],
            [96, 16],
            [100, 12],
            [103, 2],
            [105, 10],
            [109, 14],
            [108, 21],
            [116, 23],
            [121, 30],
            [120, 36],
            [124, 39],
            [128, 35],
            [129, 41],
            [135, 44],
            [141, 53],
            [140, 59],
            [155, 60],
            [162, 54],
            [170, 62],
            [178, 66],
            [160, 70],
            [132, 72],
            [105, 75],
            [80, 73],
            [64, 70],
            [42, 66],
            [42, 55],
            [39, 47],
            [35, 45],
            [29, 43],
            [27, 41],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'japan',
      properties: { name: 'Japan' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [130, 32],
            [134, 33],
            [140, 36],
            [142, 42],
            [145, 44],
            [140, 41],
            [136, 36],
            [130, 33],
            [130, 32],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'indonesia-se',
      properties: { name: 'Maritime Southeast Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [96, 5],
            [104, -5],
            [114, -8],
            [118, -2],
            [117, 5],
            [108, 2],
            [102, 1],
            [96, 5],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'australia',
      properties: { name: 'Australia' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [114, -22],
            [115, -34],
            [129, -32],
            [138, -36],
            [147, -38],
            [153, -28],
            [150, -20],
            [143, -11],
            [136, -12],
            [130, -12],
            [122, -17],
            [114, -22],
          ],
        ],
      },
    },
    {
      type: 'Feature',
      id: 'new-zealand',
      properties: { name: 'New Zealand' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [166, -46],
            [172, -44],
            [178, -38],
            [174, -35],
            [172, -41],
            [166, -46],
          ],
        ],
      },
    },
  ],
};

export const WORLD_LAND_GEOJSON: GeoFeatureCollection = {
  type: 'FeatureCollection',
  features: RAW_WORLD_LAND_GEOJSON.features.map((feature) => ({
    ...feature,
    geometry: {
      ...feature.geometry,
      coordinates: feature.geometry.coordinates.map((ring) => [...ring].reverse()),
    },
  })),
};

export interface CountryGeoMeta {
  code: string;
  countryName: string;
  macroRegion: string;
  lat: number;
  lon: number;
}

export const COUNTRY_GEO_COORDS: Record<string, CountryGeoMeta> = {
  US: { code: 'US', countryName: 'United States', macroRegion: 'North America', lat: 39.5, lon: -98.35 },
  CA: { code: 'CA', countryName: 'Canada', macroRegion: 'North America', lat: 56.1, lon: -106.3 },
  MX: { code: 'MX', countryName: 'Mexico', macroRegion: 'North America', lat: 23.6, lon: -102.5 },
  BR: { code: 'BR', countryName: 'Brazil', macroRegion: 'South America', lat: -14.2, lon: -51.9 },
  AR: { code: 'AR', countryName: 'Argentina', macroRegion: 'South America', lat: -38.4, lon: -63.6 },
  CL: { code: 'CL', countryName: 'Chile', macroRegion: 'South America', lat: -33.4, lon: -70.6 },
  CO: { code: 'CO', countryName: 'Colombia', macroRegion: 'South America', lat: 4.6, lon: -74.3 },
  GB: { code: 'GB', countryName: 'United Kingdom', macroRegion: 'Western Europe', lat: 54.0, lon: -2.0 },
  IE: { code: 'IE', countryName: 'Ireland', macroRegion: 'Western Europe', lat: 53.3, lon: -8.0 },
  DE: { code: 'DE', countryName: 'Germany', macroRegion: 'Western Europe', lat: 51.2, lon: 10.4 },
  NL: { code: 'NL', countryName: 'Netherlands', macroRegion: 'Western Europe', lat: 52.3, lon: 5.3 },
  FR: { code: 'FR', countryName: 'France', macroRegion: 'Western Europe', lat: 46.6, lon: 2.2 },
  BE: { code: 'BE', countryName: 'Belgium', macroRegion: 'Western Europe', lat: 50.8, lon: 4.5 },
  CH: { code: 'CH', countryName: 'Switzerland', macroRegion: 'Western Europe', lat: 46.8, lon: 8.2 },
  AT: { code: 'AT', countryName: 'Austria', macroRegion: 'Western Europe', lat: 47.5, lon: 14.5 },
  ES: { code: 'ES', countryName: 'Spain', macroRegion: 'Western Europe', lat: 40.4, lon: -3.7 },
  IT: { code: 'IT', countryName: 'Italy', macroRegion: 'Western Europe', lat: 42.8, lon: 12.6 },
  PT: { code: 'PT', countryName: 'Portugal', macroRegion: 'Western Europe', lat: 39.4, lon: -8.2 },
  SE: { code: 'SE', countryName: 'Sweden', macroRegion: 'Northern Europe', lat: 60.1, lon: 18.6 },
  FI: { code: 'FI', countryName: 'Finland', macroRegion: 'Northern Europe', lat: 61.9, lon: 25.7 },
  NO: { code: 'NO', countryName: 'Norway', macroRegion: 'Northern Europe', lat: 60.5, lon: 8.5 },
  DK: { code: 'DK', countryName: 'Denmark', macroRegion: 'Northern Europe', lat: 56.2, lon: 9.5 },
  PL: { code: 'PL', countryName: 'Poland', macroRegion: 'Eastern Europe', lat: 52.0, lon: 19.1 },
  CZ: { code: 'CZ', countryName: 'Czechia', macroRegion: 'Eastern Europe', lat: 49.8, lon: 15.5 },
  UA: { code: 'UA', countryName: 'Ukraine', macroRegion: 'Eastern Europe', lat: 48.4, lon: 31.2 },
  RO: { code: 'RO', countryName: 'Romania', macroRegion: 'Eastern Europe', lat: 45.9, lon: 24.9 },
  BG: { code: 'BG', countryName: 'Bulgaria', macroRegion: 'Eastern Europe', lat: 42.7, lon: 25.5 },
  HU: { code: 'HU', countryName: 'Hungary', macroRegion: 'Eastern Europe', lat: 47.1, lon: 19.5 },
  MD: { code: 'MD', countryName: 'Moldova', macroRegion: 'Eastern Europe', lat: 47.0, lon: 28.8 },
  RU: { code: 'RU', countryName: 'Russia', macroRegion: 'Eurasia', lat: 57.5, lon: 58.0 },
  BY: { code: 'BY', countryName: 'Belarus', macroRegion: 'Eurasia', lat: 53.7, lon: 27.9 },
  KZ: { code: 'KZ', countryName: 'Kazakhstan', macroRegion: 'Eurasia', lat: 48.0, lon: 66.9 },
  TR: { code: 'TR', countryName: 'Turkey', macroRegion: 'Eurasia', lat: 39.0, lon: 35.2 },
  AE: { code: 'AE', countryName: 'United Arab Emirates', macroRegion: 'Middle East', lat: 24.2, lon: 54.4 },
  IL: { code: 'IL', countryName: 'Israel', macroRegion: 'Middle East', lat: 31.5, lon: 34.8 },
  SA: { code: 'SA', countryName: 'Saudi Arabia', macroRegion: 'Middle East', lat: 23.9, lon: 45.1 },
  IR: { code: 'IR', countryName: 'Iran', macroRegion: 'Middle East', lat: 32.4, lon: 53.7 },
  IN: { code: 'IN', countryName: 'India', macroRegion: 'South Asia', lat: 21.0, lon: 78.9 },
  PK: { code: 'PK', countryName: 'Pakistan', macroRegion: 'South Asia', lat: 30.4, lon: 69.3 },
  BD: { code: 'BD', countryName: 'Bangladesh', macroRegion: 'South Asia', lat: 23.7, lon: 90.3 },
  CN: { code: 'CN', countryName: 'China', macroRegion: 'East Asia', lat: 35.8, lon: 104.2 },
  HK: { code: 'HK', countryName: 'Hong Kong', macroRegion: 'East Asia', lat: 22.3, lon: 114.2 },
  JP: { code: 'JP', countryName: 'Japan', macroRegion: 'East Asia', lat: 36.2, lon: 138.2 },
  KR: { code: 'KR', countryName: 'South Korea', macroRegion: 'East Asia', lat: 36.5, lon: 127.8 },
  TW: { code: 'TW', countryName: 'Taiwan', macroRegion: 'East Asia', lat: 23.7, lon: 121.0 },
  SG: { code: 'SG', countryName: 'Singapore', macroRegion: 'Southeast Asia', lat: 1.35, lon: 103.8 },
  VN: { code: 'VN', countryName: 'Vietnam', macroRegion: 'Southeast Asia', lat: 14.1, lon: 108.3 },
  TH: { code: 'TH', countryName: 'Thailand', macroRegion: 'Southeast Asia', lat: 15.8, lon: 101.0 },
  MY: { code: 'MY', countryName: 'Malaysia', macroRegion: 'Southeast Asia', lat: 4.2, lon: 101.9 },
  ID: { code: 'ID', countryName: 'Indonesia', macroRegion: 'Southeast Asia', lat: -2.5, lon: 118.0 },
  PH: { code: 'PH', countryName: 'Philippines', macroRegion: 'Southeast Asia', lat: 12.8, lon: 121.8 },
  AU: { code: 'AU', countryName: 'Australia', macroRegion: 'Oceania', lat: -25.3, lon: 133.8 },
  NZ: { code: 'NZ', countryName: 'New Zealand', macroRegion: 'Oceania', lat: -41.3, lon: 174.7 },
  ZA: { code: 'ZA', countryName: 'South Africa', macroRegion: 'Africa', lat: -30.5, lon: 22.9 },
  EG: { code: 'EG', countryName: 'Egypt', macroRegion: 'Africa', lat: 26.8, lon: 30.8 },
  NG: { code: 'NG', countryName: 'Nigeria', macroRegion: 'Africa', lat: 9.1, lon: 8.7 },
  KE: { code: 'KE', countryName: 'Kenya', macroRegion: 'Africa', lat: -0.02, lon: 37.9 },
  MA: { code: 'MA', countryName: 'Morocco', macroRegion: 'Africa', lat: 31.8, lon: -7.1 },
};

export interface ThreatLandscapeIndicator {
  indicator: string;
  type: string;
  confidenceScore: number;
  riskLevel: ConfidenceRiskLevel;
  networkSegment: string;
  sources: string[];
}

export interface ThreatClusterPoint {
  countryCode: string;
  countryName: string;
  macroRegion: string;
  lat: number;
  lon: number;
  count: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  maxScore: number;
  avgScore: number;
  sharePercent: number;
  dominantTier: 'Critical' | 'High' | 'Medium' | 'Low';
  indicators: ThreatLandscapeIndicator[];
}

export interface MacroRegionSummary {
  macroRegion: string;
  count: number;
  criticalCount: number;
  countries: string[];
  sharePercent: number;
}

export interface ThreatLandscapeData {
  thresholdFilter: HeatmapThresholdFilter;
  clusters: ThreatClusterPoint[];
  macroRegions: MacroRegionSummary[];
  maxClusterCount: number;
  totalEvaluatedIocs: number;
  totalMatchedIocs: number;
  geolocatedIocCount: number;
  unattributedCount: number;
  unattributedIndicators: ThreatLandscapeIndicator[];
  topCluster: ThreatClusterPoint | null;
}

export function resolveCountryGeo(raw: string | null | undefined): CountryGeoMeta | null {
  const code = normalizeCountryCode(raw);
  if (!code) return null;
  const upper = code.toUpperCase();
  if (upper in COUNTRY_GEO_COORDS) {
    return COUNTRY_GEO_COORDS[upper];
  }
  return null;
}

export function aggregateThreatLandscape(
  lookupResults: LookupResult[],
  options: {
    thresholdFilter?: HeatmapThresholdFilter;
  } = {},
): ThreatLandscapeData {
  const thresholdFilter: HeatmapThresholdFilter = options.thresholdFilter ?? 'high_confidence';
  const confidenceByIndicator = computeAllIocConfidenceScores(lookupResults);

  const byIndicator = new Map<string, LookupResult[]>();
  for (const r of lookupResults) {
    const key = r.indicator.trim().toLowerCase();
    if (!key) continue;
    const list = byIndicator.get(key) || [];
    list.push(r);
    byIndicator.set(key, list);
  }

  let totalEvaluatedIocs = 0;
  let totalMatchedIocs = 0;
  const geolocatedIndKeys = new Set<string>();
  const unattributedIndicators: ThreatLandscapeIndicator[] = [];

  const clusterAccum = new Map<
    string,
    {
      geo: CountryGeoMeta;
      indicators: Map<string, ThreatLandscapeIndicator>;
    }
  >();

  for (const [indKey, rows] of byIndicator.entries()) {
    const conf = confidenceByIndicator.get(indKey);
    if (!conf || conf.confidenceScore === null || conf.riskLevel === 'Unknown') {
      continue;
    }

    totalEvaluatedIocs += 1;
    const score = conf.confidenceScore;

    if (thresholdFilter === 'high_confidence' && score < 50) continue;
    if (thresholdFilter === 'critical_only' && score < 75) continue;

    totalMatchedIocs += 1;

    const primaryIndicator = rows[0].indicator;
    const primaryType = rows[0].type;
    const sources = Array.from(new Set(rows.map((r) => r.source).filter(Boolean)));
    const detailsList = rows.map((r) => r.details || {});
    const networkSegment = formatNetworkSegment(primaryIndicator, primaryType, detailsList);

    const item: ThreatLandscapeIndicator = {
      indicator: primaryIndicator,
      type: primaryType,
      confidenceScore: score,
      riskLevel: conf.riskLevel,
      networkSegment,
      sources,
    };

    const seenCountries = new Set<string>();
    for (const details of detailsList) {
      const countryRaw = details.Country ?? details.country;
      if (countryRaw === undefined || countryRaw === null || String(countryRaw).trim() === '') {
        continue;
      }
      const geo = resolveCountryGeo(String(countryRaw));
      if (!geo || seenCountries.has(geo.code)) continue;
      seenCountries.add(geo.code);

      if (!clusterAccum.has(geo.code)) {
        clusterAccum.set(geo.code, { geo, indicators: new Map() });
      }
      clusterAccum.get(geo.code)!.indicators.set(indKey, item);
      geolocatedIndKeys.add(indKey);
    }

    if (seenCountries.size === 0) {
      unattributedIndicators.push(item);
    }
  }

  const geolocatedIocCount = geolocatedIndKeys.size;
  const shareDenominator = Math.max(1, geolocatedIocCount);

  const clusters: ThreatClusterPoint[] = Array.from(clusterAccum.values())
    .map(({ geo, indicators }) => {
      const list = Array.from(indicators.values()).sort(
        (a, b) => b.confidenceScore - a.confidenceScore || a.indicator.localeCompare(b.indicator),
      );
      const count = list.length;
      const criticalCount = list.filter((i) => i.riskLevel === 'Critical').length;
      const highCount = list.filter((i) => i.riskLevel === 'High').length;
      const mediumCount = list.filter((i) => i.riskLevel === 'Medium').length;
      const lowCount = list.filter((i) => i.riskLevel === 'Low').length;
      const maxScore = count > 0 ? Math.max(...list.map((i) => i.confidenceScore)) : 0;
      const avgScore =
        count > 0 ? Math.round(list.reduce((sum, i) => sum + i.confidenceScore, 0) / count) : 0;

      const dominantTier: ThreatClusterPoint['dominantTier'] =
        criticalCount > 0
          ? 'Critical'
          : highCount > 0
            ? 'High'
            : mediumCount > 0
              ? 'Medium'
              : 'Low';

      return {
        countryCode: geo.code,
        countryName: geo.countryName,
        macroRegion: geo.macroRegion,
        lat: geo.lat,
        lon: geo.lon,
        count,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        maxScore,
        avgScore,
        sharePercent: Math.round((count / shareDenominator) * 100),
        dominantTier,
        indicators: list,
      };
    })
    .sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      if (b.criticalCount !== a.criticalCount) return b.criticalCount - a.criticalCount;
      if (b.maxScore !== a.maxScore) return b.maxScore - a.maxScore;
      return a.countryCode.localeCompare(b.countryCode);
    });

  const macroMap = new Map<
    string,
    { indKeys: Set<string>; criticalKeys: Set<string>; countries: Set<string> }
  >();

  for (const cluster of clusters) {
    if (!macroMap.has(cluster.macroRegion)) {
      macroMap.set(cluster.macroRegion, {
        indKeys: new Set(),
        criticalKeys: new Set(),
        countries: new Set(),
      });
    }
    const acc = macroMap.get(cluster.macroRegion)!;
    acc.countries.add(cluster.countryCode);
    for (const item of cluster.indicators) {
      const k = item.indicator.toLowerCase();
      acc.indKeys.add(k);
      if (item.riskLevel === 'Critical') acc.criticalKeys.add(k);
    }
  }

  const macroRegions: MacroRegionSummary[] = Array.from(macroMap.entries())
    .map(([macroRegion, acc]) => ({
      macroRegion,
      count: acc.indKeys.size,
      criticalCount: acc.criticalKeys.size,
      countries: Array.from(acc.countries).sort(),
      sharePercent: Math.round((acc.indKeys.size / shareDenominator) * 100),
    }))
    .sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      if (b.criticalCount !== a.criticalCount) return b.criticalCount - a.criticalCount;
      return a.macroRegion.localeCompare(b.macroRegion);
    });

  unattributedIndicators.sort((a, b) => b.confidenceScore - a.confidenceScore);

  const maxClusterCount =
    clusters.length > 0 ? Math.max(...clusters.map((c) => c.count)) : 0;

  return {
    thresholdFilter,
    clusters,
    macroRegions,
    maxClusterCount,
    totalEvaluatedIocs,
    totalMatchedIocs,
    geolocatedIocCount,
    unattributedCount: unattributedIndicators.length,
    unattributedIndicators,
    topCluster: clusters[0] ?? null,
  };
}
