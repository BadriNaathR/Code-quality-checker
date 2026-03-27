export const API_URL = '/api';

export const fetchApi = async (endpoint: string, options?: RequestInit) => {
  const isFormData = options?.body instanceof FormData;
  const headers: any = { ...options?.headers };

  if (!isFormData) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || error.error || 'API Request failed');
  }

  return response.json();
};
