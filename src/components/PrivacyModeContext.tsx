import { createContext, useContext } from 'react';

export const PrivacyModeContext = createContext<boolean>(false);

export function usePrivacyMode(): boolean {
  return useContext(PrivacyModeContext);
}
