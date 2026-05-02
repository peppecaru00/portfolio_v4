export interface Project {
  id: string;
  title: string;
  category: string;
  year: string;
  image: string;
  videoUrl?: string;
  aspectRatio?: string;
  description?: string;
  metaData?: Record<string, any>;
}

const metaFiles = import.meta.glob("/public/projects/*/meta.json", {
  eager: true,
  import: "default",
});
const coverFiles = import.meta.glob("/public/projects/*/cover.*");
const videoFiles = import.meta.glob("/public/projects/*/*.mp4");

export const projects: Project[] = Object.entries(metaFiles).map(
  ([path, meta]: [string, any]) => {
    const parts = path.split("/");
    const id = parts[parts.length - 2];

    // Extract specific properties and keep the rest in metaData
    const {
      title,
      category,
      year,
      videoUrl,
      aspectRatio,
      description,
      ...rest
    } = meta;

    const projectCoverPrefix = `/public/projects/${id}/cover.`;
    const covers = Object.keys(coverFiles).filter((f) =>
      f.startsWith(projectCoverPrefix),
    );

    let resolvedImage = "";
    let resolvedVideo = videoUrl;

    // 1. Resolve Image from coverFiles
    for (const file of covers) {
      if (!file.endsWith(".mp4") && !file.endsWith(".webm")) {
        resolvedImage = file.replace("/public", "");
      }
    }

    // 2. Resolve Video with priority: meta.json > specific mp4 > cover mp4
    const projectVideoPrefix = `/public/projects/${id}/`;
    const folderVideos = Object.keys(videoFiles).filter((f) =>
      f.startsWith(projectVideoPrefix),
    );

    if (!resolvedVideo) {
      // Find the first video that is NOT a cover
      const mainVideo = folderVideos.find((f) => !f.includes("/cover."));
      if (mainVideo) {
        resolvedVideo = mainVideo.replace("/public", "");
      } else {
        // Fallback to cover video
        const coverVideo = folderVideos.find((f) => f.includes("/cover."));
        if (coverVideo) {
          resolvedVideo = coverVideo.replace("/public", "");
        }
      }
    }

    return {
      id,
      title: title || id,
      category: category || "",
      year: year || "",
      image: resolvedImage,
      videoUrl: resolvedVideo,
      aspectRatio: aspectRatio,
      description: description,
      metaData: rest,
    };
  },
);
