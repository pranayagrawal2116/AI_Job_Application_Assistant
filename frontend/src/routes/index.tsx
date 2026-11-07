import { createBrowserRouter, Navigate } from 'react-router-dom';
import { AuthLayout } from '@/layouts/AuthLayout';
import { DashboardLayout } from '@/layouts/DashboardLayout';
import { ProtectedRoute } from '@/components/common/ProtectedRoute';

import { LoginPage } from '@/features/auth/LoginPage';
import { RegisterPage } from '@/features/auth/RegisterPage';
import { OnboardingWizard } from '@/features/onboarding/OnboardingWizard';
import { DashboardPage } from '@/features/dashboard/DashboardPage';
import { JobsPage } from '@/features/jobs/JobsPage';
import { ProfilePage } from '@/features/profile/ProfilePage';
import { ApplicationsPage } from '@/features/applications/ApplicationsPage';
import { ApplicationPreparerPage } from '@/features/applications/ApplicationPreparerPage';
import { SettingsPage } from '@/features/settings/SettingsPage';

export const router = createBrowserRouter([
  // Public Auth Routes
  {
    element: <AuthLayout />,
    children: [
      { path: '/login', element: <LoginPage /> },
      { path: '/register', element: <RegisterPage /> },
    ],
  },

  // Protected Onboarding
  {
    path: '/onboarding',
    element: <ProtectedRoute />,
    children: [
      { index: true, element: <OnboardingWizard /> },
    ],
  },

  // Protected App Routes
  {
    element: <ProtectedRoute />,
    children: [
      {
        element: <DashboardLayout />,
        children: [
          { path: '/', element: <Navigate to="/dashboard" replace /> },
          { path: '/dashboard', element: <DashboardPage /> },
          { path: '/jobs', element: <JobsPage /> },
          { path: '/profile', element: <ProfilePage /> },
          { path: '/applications', element: <ApplicationsPage /> },
          { path: '/applications/:id/prepare', element: <ApplicationPreparerPage /> },
          { path: '/settings', element: <SettingsPage /> },
        ],
      },
    ],
  },

  // Catch-all fallback
  {
    path: '*',
    element: <Navigate to="/dashboard" replace />,
  },
]);
