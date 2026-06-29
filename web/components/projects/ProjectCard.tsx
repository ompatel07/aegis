import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn, gradeColor } from "@/lib/utils";
import type { Grade, Project } from "@/lib/types";
import { GitBranch } from "lucide-react";

export function ProjectCard({ project, grade }: { project: Project; grade?: Grade }) {
  return (
    <Link href={`/projects/${project.id}`}>
      <Card className="h-full transition-shadow hover:shadow-md">
        <CardHeader className="flex flex-row items-start justify-between space-y-0">
          <div className="min-w-0">
            <CardTitle className="truncate">{project.name}</CardTitle>
            {project.description ? (
              <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{project.description}</p>
            ) : null}
          </div>
          {grade ? (
            <span className={cn("text-3xl font-bold", gradeColor(grade))}>{grade}</span>
          ) : null}
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          {project.language ? (
            <Badge className="border-border bg-secondary text-secondary-foreground capitalize">
              {project.language}
            </Badge>
          ) : null}
          <span className="flex items-center gap-1">
            <GitBranch className="h-3 w-3" /> {project.default_branch}
          </span>
          {project.repo_url ? <span className="truncate">{project.repo_url}</span> : null}
        </CardContent>
      </Card>
    </Link>
  );
}
