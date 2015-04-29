% ------------------------------------------------------------------------------
% Classe projet
% 
% Un environnement agréable pour la rédaction des projets.
% Usage :
%  - \documentclass[]{projet}
%    Les options de documentclass sont transmises au style article
% 
% Plusieurs commandes doivent être définies :
%  - \newcommand{\myname}{nom de l'auteur}
%  - \newcommand{\mysupervisor}{nom de l'encadrant du projet}
%  - \newcommand{\myreviewer}{nom du relecteur pour la soutenance}
%  - \newcommand{\mydate}{la date du projet}
%  - \newcommand{\mytitle}{titre du projet}
%  - \newcommand{\mypicture}{nom de fichier d'une image d'illustration : peut être au format pdf, png ou jpg}
%  - \newcommand{\myabstract}{résumé du projet : il ne faut pas qu'il dépasse de la première page}
% 
% Ensuite la commande :
%  - \makemytitle{}
% permet de créer le titre
% 
% ------------------------------------------------------------------------------

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{projet}[2012/10/26 v0.1 style pour les projets de M1 du Département d'Informatique de l'Université de Caen]
\typeout{v0.1 style pour les projets de M1 du Département d'Informatique de l'Université de Caen}
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
\ProcessOptions\relax
\LoadClass[a4paper]{article} 

% Packages
\RequirePackage[utf8]{inputenc}
\RequirePackage[french]{babel}
\RequirePackage{MnSymbol,latexsym,eurosym,wasysym}
\RequirePackage{bbm}  % \mathbbm{N}, \mathbbmss \mathbbmtt
\RequirePackage{fancyhdr} 
\RequirePackage{lastpage}
\RequirePackage{calc,ifthen,xspace,url}
\RequirePackage{graphicx}
\RequirePackage{wrapfig}
\RequirePackage{color}
\RequirePackage{framed}
\RequirePackage{lipsum}
\usepackage[french]{babel}
\usepackage{hyperref}
\usepackage[toc,section=section]{glossaries}
\usepackage{hhline}
\usepackage{listings}
\lstset{ % General setup for the package
	language=bash,
	basicstyle=\small\sffamily,
	numbers=left,
 	numberstyle=\tiny,
	frame=tb,
	tabsize=4,
	columns=fixed,
	showstringspaces=false,
	showtabs=false,
	keepspaces,
	breaklines=true,
	moredelim=[is][\underbar]{_}{_},,
}
\usepackage{xcolor}
\hypersetup{
    colorlinks,
    linkcolor={black!80!black},
    citecolor={blue!50!black},
    urlcolor={blue!80!black}
}
\setlength{\textheight}{210mm}
\setlength{\textwidth}{150mm}
\setlength{\oddsidemargin}{5mm}
\setlength{\evensidemargin}{5mm} 
\setlength{\topmargin}{0mm}
\setlength{\headheight}{0mm}
%%\setlength{\parindent}{0pt}

\definecolor{GreycColor}{rgb}{0.471,0.051,0.408}

\DeclareGraphicsExtensions{.pdf,.png,.jpg}
\graphicspath{{images/}}

% Affichage du titre
\newcommand{\makemytitle}[1]{%
 \thispagestyle{empty}
 \hrule height 1mm
 \vspace*{1mm}
 \begin{minipage}[b]{5cm}
  \includegraphics[width=5cm]{unicaen_logo_rvb_noir_V2}
 \end{minipage} \hfill
 \begin{minipage}[b]{10cm}
   \flushright\sf \vspace*{5mm}
   {\setlength{\baselineskip}{2.0\baselineskip}
     \textcolor{GreycColor}{\Large Université de Caen} \\
     {\Large Département d'Informatique} \\
     \textcolor{GreycColor}{\Large Master 1} \\
     {\Large Projet annuel}\\
   \par}
 \end{minipage} \vspace{1mm}
 \hrule height 1mm \vspace{5mm}
 \begin{center}
   \textcolor{GreycColor}{\sf\fontsize{52}{52}\selectfont \mytitle}
 \end{center}\vspace{1mm}
 \hrule height 1mm \vspace{5mm}
 \begin{minipage}[b]{10cm}
  \includegraphics[height=5cm]{\mypicture}
  
  \myquote
 \end{minipage} \hfill
 \begin{minipage}[b]{5cm}
   \flushright\sf \vspace*{5mm}
   {\setlength{\baselineskip}{2.0\baselineskip}
     {\sf\large Projet réalisé par \textcolor{GreycColor}{\myname}} \\
     {\sf\large Encadrant : \mysupervisor} \\
     {\sf\large Relecteur : \myreviewer} \\
     {\sf\large \mydate} \\
   \par}
 \end{minipage} \vspace{1mm}
 \hrule height 1mm \vspace{5mm}
 \begin{framed}
  \centerline{\sf\Large\ Résumé} \vspace*{1mm} \sf
  \myabstract
 \end{framed}

 \newpage
}

% Fancyheadings
\pagestyle{fancy}
\fancyhead{} % clear all header fields
%\fancyhead[L]{}
\fancyhead[R]{\mytitle}
\fancyfoot{} % clear all footer fields
\fancyfoot[L]{\myname}
\fancyfoot[R]{\thepage/\pageref{LastPage}}
\renewcommand{\headrulewidth}{0.5mm}
\renewcommand{\footrulewidth}{0.5mm}

\newtheorem{definition}{Definition}
\newtheorem{remark}{Remark}
\newtheorem{example}{Example}
\newtheorem{theorem}{Theorem}
\newtheorem{proposition}{Proposition}
\newtheorem{lemma}{Lemma}
\newtheorem{myrule}{Rule}
\newtheorem{corollary}{Corollary}
%\newtheorem{comment}{Comment}
\newtheorem{note}{Note}
\newtheorem{problem}{Problem}
\newenvironment{proof}%
        {\noindent {\bf Proof.~} }%
        {~$\diamond$\\}

% \AtBeginDocument{\sffamily}

