package dns

// The record set this package produces lives in plan.go: BuildPlan assembles
// every record a domain needs (with the notes the DNS page shows) and
// BuildExpected derives the checkable subset from it, so the page, the .txt
// export and the live check can never disagree about what is wanted.
//
// This file is kept as the place that used to hold BuildExpected, because the
// name is part of the package's API and the reasoning above is worth keeping
// next to it.
