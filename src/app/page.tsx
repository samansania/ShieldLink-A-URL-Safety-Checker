"use client";

import * as React from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Loader2, Shield } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { analyzeTextForLinks, type AnalysisReport } from "./actions";
import Link from "next/link";

const formSchema = z.object({
  text: z.string().min(10, { message: "Please enter at least 10 characters." }),
});

export default function Home() {
  const [isLoading, setIsLoading] = React.useState(false);
  const [reports, setReports] = React.useState<AnalysisReport[]>([]);
  const { toast } = useToast();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      text: "",
    },
  });

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setIsLoading(true);
    setReports([]);

    try {
      const analysisReports = await analyzeTextForLinks(values);
      setReports(analysisReports);
      if (analysisReports.length === 0) {
        toast({
          title: "No URLs Found",
          description: "We couldn't find any URLs in the text you provided.",
        });
      }
    } catch (error) {
      console.error("Analysis failed:", error);
      toast({
        variant: "destructive",
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "An unexpected error occurred. Please try again.",
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center bg-gray-900 text-white p-4">
      <div
        className="absolute inset-0 -z-10 bg-cover bg-center"
        style={{ backgroundImage: "url('https://images.unsplash.com/photo-1510915228340-29c85a43dcfe?q=80&w=2070&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D')" }}
        data-ai-hint="phishing security"
      ></div>
      <div className="absolute inset-0 -z-10 bg-black/70"></div>

      <div className="w-full max-w-2xl space-y-8">
        <header className="text-center">
          <div className="flex justify-center mb-4">
            <Shield className="h-16 w-16 text-accent animate-pulse" />
          </div>
          <h1 className="font-merriweather text-4xl md:text-5xl font-bold tracking-tight mb-2 flex items-center justify-center gap-2">
            ShieldLink
          </h1>
          <p className="text-gray-200 text-lg">
            Paste any text below. We'll find all links and create a secure shield for each one.
          </p>
        </header>

        <Card className="shadow-xl rounded-lg bg-card/90 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-card-foreground">
              Analyze Content
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                <FormField
                  control={form.control}
                  name="text"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel htmlFor="text-input" className="text-card-foreground">Paste email body or any text or link</FormLabel>
                      <FormControl>
                        <Textarea
                          id="text-input"
                          placeholder="Paste your suspicious email content here..."
                          {...field}
                          aria-label="Text content input"
                          className="bg-background/80 placeholder:text-muted-foreground/80 min-h-[120px]"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" disabled={isLoading} className="w-full bg-accent hover:bg-accent/90 text-accent-foreground">
                  {isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    "Find & Shield Links"
                  )}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>

        {isLoading && (
          <div className="flex justify-center items-center p-6">
            <Loader2 className="mr-2 h-8 w-8 animate-spin text-accent" />
            <span className="text-gray-200">Analyzing links...</span>
          </div>
        )}

        {reports.length > 0 && (
          <Card className="shadow-xl rounded-lg animate-in fade-in duration-500 bg-card/95 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-card-foreground">Analysis Complete</CardTitle>
              <CardDescription className="text-muted-foreground">{reports.length} URL(s) found. Open them through our shield.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {reports.map((report, index) => {
                  const reportData = report.results ? Buffer.from(JSON.stringify(report.results)).toString('base64') : '';
                  const isSafe = report.results?.content.isSafe ?? false;

                  return (
                    <div key={index} className="flex flex-col items-start p-4 border rounded-lg bg-background/50">
                      <span className="font-mono text-sm break-all text-muted-foreground">{report.url}</span>
                      {report.error ? (
                        <p className="text-destructive mt-2">Analysis Failed: {report.error}</p>
                      ) : (
                        <Button asChild className={`mt-2 ${isSafe ? 'bg-blue-600 hover:bg-blue-700' : 'bg-red-600 hover:bg-red-700'} text-white`}>
                          <Link href={`/shield?data=${reportData}`}>
                            <Shield className="mr-2 h-4 w-4" />
                            Open Shielded Link
                          </Link>
                        </Button>
                      )}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
