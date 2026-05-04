import { projects } from "~/data/projects";
import type { Project } from "~/data/projects";

export const useProjects = () => {
  const config = useRuntimeConfig();
  const baseURL = config.app.baseURL;

  const resolvedProjects = projects.map((p) => ({
    ...p,
    image: p.image && !p.image.startsWith("http") ? `${baseURL}${p.image}` : p.image,
    videoUrl: p.videoUrl && !p.videoUrl.startsWith("http") ? `${baseURL}${p.videoUrl}` : p.videoUrl,
    coverVideo: p.coverVideo && !p.coverVideo.startsWith("http") ? `${baseURL}${p.coverVideo}` : p.coverVideo,
  }));

  const getProjectById = (id: string): Project | undefined => {
    return resolvedProjects.find((p) => p.id === id);
  };

  return {
    projects: resolvedProjects,
    getProjectById,
  };
};

