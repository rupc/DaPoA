// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import "@fontsource/inter/variable.css";
import "./index.css";
import Plausible from "plausible-tracker";
import React from "react";
import ReactDOM from "react-dom/client";
import {
  createBrowserRouter,
  Navigate,
  RouterProvider,
} from "react-router-dom";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";

import { toast } from "react-hot-toast";
import { Root } from "./routes/Root";
import { Ended } from "./routes/Ended";
// import { Home } from "./routes/Home";
// import { Connect } from "./routes/Connect";
// import { Setup } from "./routes/Setup";
// import { Migrate } from "./routes/Migrate";
// import { Claim } from "./routes/Claim";

const plausible = Plausible({});
plausible.enableAutoPageviews();

const queryClient = new QueryClient({
  defaultOptions: {
    mutations: {
      onError(error) {
        toast.error(String(error));
      },
    },
  },
});

const router = createBrowserRouter([
  {
    path: "/",
    element: <Root />,
    children: [
      {
        path: "",
        element: <Ended />,
      },
      // {
      //   path: "",
      //   element: <Home />,
      // },
      // {
      //   path: "connect",
      //   element: <Connect />,
      // },
      // {
      //   path: "setup",
      //   element: <Setup />,
      // },
      // {
      //   path: "migrate",
      //   element: <Migrate />,
      // },
      // {
      //   path: "claim",
      //   element: <Claim />,
      // },
      {
        path: "*",
        element: <Navigate to="/" replace />,
      },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>
);
